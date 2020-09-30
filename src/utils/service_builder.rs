// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Assemble the service from a user-defined config
//!
//! The service builder is required to bootstrap all the components based on a
//! provided configuration.
use super::global_config::GlobalConfigBuilder;
use crate::authenticators::direct_authenticator::DirectAuthenticator;
use crate::authenticators::unix_peer_credentials_authenticator::UnixPeerCredentialsAuthenticator;
use crate::authenticators::{Authenticate, AuthenticatorConfig};
use crate::back::{
    backend_handler::{BackEndHandler, BackEndHandlerBuilder},
    dispatcher::DispatcherBuilder,
};
use crate::front::listener::{ListenerConfig, ListenerType};
use crate::front::{
    domain_socket::DomainSocketListenerBuilder, front_end::FrontEndHandler,
    front_end::FrontEndHandlerBuilder, listener::Listen,
};
use crate::key_info_managers::on_disk_manager::{
    OnDiskKeyInfoManagerBuilder, DEFAULT_MAPPINGS_PATH,
};
use crate::key_info_managers::{KeyInfoManagerConfig, KeyInfoManagerType, ManageKeyInfo};
use crate::providers::{core_provider::CoreProviderBuilder, Provide, ProviderConfig};
use log::{error, info, warn, LevelFilter};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{BodyType, ProviderID};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use threadpool::{Builder as ThreadPoolBuilder, ThreadPool};

#[cfg(feature = "mbed-crypto-provider")]
use crate::providers::mbed_crypto_provider::MbedCryptoProviderBuilder;
#[cfg(feature = "pkcs11-provider")]
use crate::providers::pkcs11_provider::Pkcs11ProviderBuilder;
#[cfg(feature = "tpm-provider")]
use crate::providers::tpm_provider::TpmProviderBuilder;

const WIRE_PROTOCOL_VERSION_MINOR: u8 = 0;
const WIRE_PROTOCOL_VERSION_MAJOR: u8 = 1;

/// Default value for the limit on the request body size (in bytes) - equal to 1MB
const DEFAULT_BODY_LEN_LIMIT: usize = 1 << 20;

/// Default value for the limit on the buffer size for response (in bytes) - equal to 1MB
pub const DEFAULT_BUFFER_SIZE_LIMIT: usize = 1 << 20;

type KeyInfoManager = Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>;
type Provider = Arc<dyn Provide + Send + Sync>;
type Authenticator = Box<dyn Authenticate + Send + Sync>;

/// Core settings
///
/// See the config.toml file for a description of each field.
#[derive(Copy, Clone, Deserialize, Debug)]
#[allow(missing_docs)]
pub struct CoreSettings {
    pub thread_pool_size: Option<usize>,
    pub idle_listener_sleep_duration: Option<u64>,
    pub log_level: Option<LevelFilter>,
    pub log_timestamp: Option<bool>,
    pub body_len_limit: Option<usize>,
    pub log_error_details: Option<bool>,
    pub allow_root: Option<bool>,
    pub buffer_size_limit: Option<usize>,
}

/// Configuration of Parsec
///
/// See the config.toml file for a description of each field.
#[derive(Deserialize, Debug)]
#[allow(missing_docs)]
pub struct ServiceConfig {
    pub core_settings: CoreSettings,
    pub listener: ListenerConfig,
    pub authenticator: Option<Vec<AuthenticatorConfig>>,
    pub key_manager: Option<Vec<KeyInfoManagerConfig>>,
    pub provider: Option<Vec<ProviderConfig>>,
}

/// Service component builder and assembler
///
/// Entity responsible for converting a Parsec service configuration into a fully formed service.
/// Each component is independently created after which its ownership can be passed to the previous
/// component in the ownership chain. The service's ownership is then passed in the form of
/// ownership of a `FrontEndHandler` instance.
#[derive(Copy, Clone, Debug)]
pub struct ServiceBuilder;

impl ServiceBuilder {
    /// Evaluate the provided configuration and assemble a service based on it. If the configuration contains
    /// any errors or inconsistencies, an `Err` is returned.
    ///
    /// # Errors
    /// * if any of the fields specified in the configuration are inconsistent (e.g. key info manager with name 'X'
    /// requested for a certain provider does not exist) or if required fields are missing, an error of kind
    /// `InvalidData` is returned with a string describing the cause more accurately.
    pub fn build_service(config: &ServiceConfig) -> Result<FrontEndHandler> {
        GlobalConfigBuilder::new()
            .with_log_error_details(config.core_settings.log_error_details.unwrap_or(false))
            .with_buffer_size_limit(
                config
                    .core_settings
                    .buffer_size_limit
                    .unwrap_or(DEFAULT_BUFFER_SIZE_LIMIT),
            )
            .build();

        let key_info_managers =
            build_key_info_managers(config.key_manager.as_ref().unwrap_or(&Vec::new()))?;

        let providers = build_providers(
            config.provider.as_ref().unwrap_or(&Vec::new()),
            key_info_managers,
        );

        if providers.is_empty() {
            error!("Parsec needs at least one provider to start. No valid provider could be created from the configuration.");
            return Err(Error::new(ErrorKind::InvalidData, "need one provider"));
        }

        // Build authenticators based on configuration. The function below will always return a vector with
        // at least one entry, because if no authenticators are specified in configuration, then the system will
        // fall back to the legacy pattern of direct authentication.
        let authenticators = build_authenticators(
            config.listener.listener_type,
            config.authenticator.as_ref().unwrap_or(&Vec::new()),
        )?;

        let backend_handlers = build_backend_handlers(providers, &authenticators)?;

        let dispatcher = DispatcherBuilder::new()
            .with_backends(backend_handlers)
            .build()?;

        let mut front_end_handler_builder = FrontEndHandlerBuilder::new();
        for (auth_type, authenticator) in authenticators {
            front_end_handler_builder =
                front_end_handler_builder.with_authenticator(auth_type, authenticator);
        }
        front_end_handler_builder = front_end_handler_builder
            .with_dispatcher(dispatcher)
            .with_body_len_limit(
                config
                    .core_settings
                    .body_len_limit
                    .unwrap_or(DEFAULT_BODY_LEN_LIMIT),
            );

        Ok(front_end_handler_builder.build()?)
    }

    /// Construct the service IPC front component and return ownership to it.
    pub fn start_listener(config: ListenerConfig) -> Result<Box<dyn Listen>> {
        let listener = match config.listener_type {
            ListenerType::DomainSocket => DomainSocketListenerBuilder::new()
                .with_timeout(Duration::from_millis(config.timeout))
                .build(),
        }?;

        Ok(Box::new(listener))
    }

    /// Construct the thread pool that will be used to process all service requests.
    pub fn build_threadpool(num_threads: Option<usize>) -> ThreadPool {
        let mut threadpool_builder = ThreadPoolBuilder::new();
        if let Some(num_threads) = num_threads {
            threadpool_builder = threadpool_builder.num_threads(num_threads);
        }
        threadpool_builder.build()
    }
}

fn build_backend_handlers(
    mut providers: Vec<(ProviderID, Provider)>,
    authenticators: &[(AuthType, Authenticator)],
) -> Result<HashMap<ProviderID, BackEndHandler>> {
    let mut map = HashMap::new();

    let mut core_provider_builder = CoreProviderBuilder::new()
        .with_wire_protocol_version(WIRE_PROTOCOL_VERSION_MINOR, WIRE_PROTOCOL_VERSION_MAJOR);

    for (_auth_type, authenticator) in authenticators {
        let authenticator_info = authenticator
            .describe()
            .map_err(|_| Error::new(ErrorKind::Other, "Failed to describe authenticator"))?;
        core_provider_builder = core_provider_builder.with_authenticator_info(authenticator_info);
    }

    for (provider_id, provider) in providers.drain(..) {
        core_provider_builder = core_provider_builder.with_provider(provider.clone());

        let backend_handler = BackEndHandlerBuilder::new()
            .with_provider(provider)
            .with_converter(Box::from(ProtobufConverter {}))
            .with_provider_id(provider_id)
            .with_content_type(BodyType::Protobuf)
            .with_accept_type(BodyType::Protobuf)
            .build()?;
        let _ = map.insert(provider_id, backend_handler);
    }

    let core_provider_backend = BackEndHandlerBuilder::new()
        .with_provider(Arc::new(core_provider_builder.build()?))
        .with_converter(Box::from(ProtobufConverter {}))
        .with_provider_id(ProviderID::Core)
        .with_content_type(BodyType::Protobuf)
        .with_accept_type(BodyType::Protobuf)
        .build()?;

    let _ = map.insert(ProviderID::Core, core_provider_backend);

    Ok(map)
}

fn build_authenticators(
    listener_type: ListenerType,
    configs: &[AuthenticatorConfig],
) -> Result<Vec<(AuthType, Authenticator)>> {
    let mut list: Vec<(AuthType, Authenticator)> = Vec::new();

    // Build authenticators from configuration entries in turn. Note that the order of these entries is
    // important. The ListAuthenticators operation will return them in this order, which is considered to
    // be preferential from the perspective of the client. The client will choose the entry at the head of
    // this list when deciding how to authenticate, unless explicit overrides are given.
    for config in configs {
        let auth_type = config.auth_type();
        if list.iter().any(|(auth, _)| *auth == auth_type) {
            warn!("Parsec currently only supports one instance of each authenticator type. Ignoring type {:?} and continuing...", auth_type);
            continue;
        }

        match config {
            AuthenticatorConfig::Direct { .. } => {
                info!("Adding direct authentication.");
                list.push((AuthType::Direct, Box::from(DirectAuthenticator {})))
            }
            AuthenticatorConfig::UnixPeerCredential { .. } => {
                if listener_type == ListenerType::DomainSocket {
                    info!("Adding peer credential authentication (supported with DomainSocket listener).");
                    list.push((
                        AuthType::PeerCredentials,
                        Box::from(UnixPeerCredentialsAuthenticator {}),
                    ))
                } else {
                    error!(
                        "Configuration specifies peer credential auth, which cannot be used with a {:?} listener.",
                        listener_type
                    );
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Authentication incompatible with listener type.",
                    ));
                }
            }
        }
    }

    if list.is_empty() {
        warn!("No authenticators specified in configuration file. Using legacy direct authentication only.");
        list.push((AuthType::Direct, Box::from(DirectAuthenticator {})));
    } else if list.len() > 1 {
        error!("Multiple authentication methods not supported in current deployments.");
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Multiple authenticators not currently supported.",
        ));
    }

    Ok(list)
}

fn build_providers(
    configs: &[ProviderConfig],
    key_info_managers: HashMap<String, KeyInfoManager>,
) -> Vec<(ProviderID, Provider)> {
    let mut list = Vec::new();
    for config in configs {
        let provider_id = config.provider_id();
        if list.iter().any(|(id, _)| *id == provider_id) {
            warn!("Parsec currently only supports one instance of each provider type. Ignoring {} and continuing...", provider_id);
            continue;
        }

        let key_info_manager = match key_info_managers.get(config.key_info_manager()) {
            Some(key_info_manager) => key_info_manager,
            None => {
                format_error!(
                    "Key info manager with specified name was not found",
                    config.key_info_manager()
                );
                continue;
            }
        };
        // The safety is checked by the fact that only one instance per provider type is enforced.
        let provider = match unsafe { get_provider(config, key_info_manager.clone()) } {
            Ok(provider) => provider,
            Err(e) => {
                format_error!(
                    &format!("Provider with ID {} cannot be created", provider_id),
                    e
                );
                continue;
            }
        };
        let _ = list.push((provider_id, provider));
    }

    list
}

// This cfg_attr is used to allow the fact that key_info_manager is not used when there is no
// providers.
#[cfg_attr(
    not(all(
        feature = "mbed-crypto-provider",
        feature = "pkcs11-provider",
        feature = "tpm-provider"
    )),
    allow(unused_variables),
    allow(clippy::match_single_binding)
)]
unsafe fn get_provider(
    config: &ProviderConfig,
    key_info_manager: KeyInfoManager,
) -> Result<Provider> {
    match config {
        #[cfg(feature = "mbed-crypto-provider")]
        ProviderConfig::MbedCrypto { .. } => {
            info!("Creating a Mbed Crypto Provider.");
            Ok(Arc::new(
                MbedCryptoProviderBuilder::new()
                    .with_key_info_store(key_info_manager)
                    .build()?,
            ))
        }
        #[cfg(feature = "pkcs11-provider")]
        ProviderConfig::Pkcs11 {
            library_path,
            slot_number,
            user_pin,
            software_public_operations,
            ..
        } => {
            info!("Creating a PKCS 11 Provider.");
            Ok(Arc::new(
                Pkcs11ProviderBuilder::new()
                    .with_key_info_store(key_info_manager)
                    .with_pkcs11_library_path(library_path.clone())
                    .with_slot_number(*slot_number)
                    .with_user_pin(user_pin.clone())
                    .with_software_public_operations(*software_public_operations)
                    .build()?,
            ))
        }
        #[cfg(feature = "tpm-provider")]
        ProviderConfig::Tpm {
            tcti,
            owner_hierarchy_auth,
            ..
        } => {
            info!("Creating a TPM Provider.");
            Ok(Arc::new(
                TpmProviderBuilder::new()
                    .with_key_info_store(key_info_manager)
                    .with_tcti(tcti)
                    .with_owner_hierarchy_auth(owner_hierarchy_auth.clone())
                    .build()?,
            ))
        }
        #[cfg(not(all(
            feature = "mbed-crypto-provider",
            feature = "pkcs11-provider",
            feature = "tpm-provider"
        )))]
        _ => {
            error!(
                "Provider \"{:?}\" chosen in the configuration was not compiled in Parsec binary.",
                config
            );
            Err(Error::new(ErrorKind::InvalidData, "provider not compiled"))
        }
    }
}

fn build_key_info_managers(
    configs: &[KeyInfoManagerConfig],
) -> Result<HashMap<String, KeyInfoManager>> {
    let mut map = HashMap::new();
    for config in configs {
        let _ = map.insert(config.name.clone(), get_key_info_manager(config)?);
    }

    Ok(map)
}

fn get_key_info_manager(config: &KeyInfoManagerConfig) -> Result<KeyInfoManager> {
    let manager = match config.manager_type {
        KeyInfoManagerType::OnDisk => {
            let store_path = if let Some(store_path) = &config.store_path {
                store_path.to_owned()
            } else {
                DEFAULT_MAPPINGS_PATH.to_string()
            };

            OnDiskKeyInfoManagerBuilder::new()
                .with_mappings_dir_path(PathBuf::from(store_path))
                .build()?
        }
    };

    Ok(Arc::new(RwLock::new(manager)))
}
