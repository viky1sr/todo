//! Binary executable daemon for todo-rest HTTP service.

use std::env;
use todo_rest::RestServiceController;
use todo_rest::server::RestApiServer;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const USAGE: &str = r#"usage: todo-rest [serve | migrate | seed | user add]
  serve      run the HTTP API (default)
  migrate    apply MariaDB migrations (TODO_MARIADB_URL, TODO_MARIADB_PASSWORD_FILE)
  seed       apply MariaDB user seed (TODO_MARIADB_URL, TODO_MARIADB_PASSWORD_FILE)
  user add   create a user from JSON on stdin:
             {"username":..,"password":..,"role":"user|admin","email":..,"national_id":..}"#;

/// Largest JSON document accepted on stdin by `user add`.
const MAX_STDIN_BYTES: u64 = 64 * 1024;

async fn accounts() -> Result<todo_database::accounts::UserStore, BoxError> {
    let upload = todo_rest::UploadConfig::from_env()?;
    todo_database::accounts::accounts_from_env(|k| upload.as_ref().is_some_and(|u| u.uses_key(k)))
        .await?
        .ok_or_else(|| "TODO_MARIADB_URL is not set".into())
}

async fn admin(args: &[String]) -> Result<(), BoxError> {
    match args {
        [cmd] if cmd == "migrate" => {
            let store = accounts().await?;
            store.migrate().await?;
            println!("MariaDB migrations applied");
            Ok(())
        }
        [cmd] if cmd == "seed" => {
            let store = accounts().await?;
            store.seed().await?;
            println!("MariaDB user seed applied");
            Ok(())
        }
        [cmd, sub] if cmd == "user" && sub == "add" => {
            use std::io::Read;
            let mut input = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(MAX_STDIN_BYTES + 1)
                .read_to_end(&mut input)?;
            if input.len() as u64 > MAX_STDIN_BYTES {
                return Err("stdin JSON too large".into());
            }
            // serde_json errors may quote input; report only the position.
            let new: todo_database::accounts::NewUser =
                serde_json::from_slice(&input).map_err(|e| {
                    format!(
                        "invalid JSON on stdin (line {}, column {})",
                        e.line(),
                        e.column()
                    )
                })?;
            let store = accounts().await?;
            let username = new.username.clone();
            let id = store.create_user(new).await?;
            println!(
                "created user id={id} username={}",
                username.trim().to_ascii_lowercase()
            );
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    todo_database::config::init_config_env()?;
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => {}
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return Ok(());
        }
        Some(_) => return admin(&args).await,
    }
    let host = env::var("REST_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("REST_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8001);

    // TODO_IPFS_BACKEND=kubo|gateway, TODO_IPFS_URL=<endpoint>.
    let controller = RestServiceController::from_env()?;
    if controller.ipfs_backend() == todo_ipfs::BackendKind::Mock {
        return Err(
            "production todo-rest requires live IPFS (TODO_IPFS_BACKEND=kubo|gateway and TODO_IPFS_URL); mock backend is prohibited in production"
                .into(),
        );
    }
    if controller.upload_config().is_none() {
        return Err(
            "production todo-rest requires upload configuration (TODO_UPLOAD_KEY_HEX or TODO_UPLOAD_KEY_HEX_FILE)"
                .into(),
        );
    }
    let mut server = RestApiServer::with_controller(&host, port, controller);
    // TODO_TLS_CERT / TODO_TLS_KEY (PEM) enable HTTPS, TLS 1.3 only.
    if let Some(acceptor) = todo_rest::tls::acceptor_from_env()? {
        server = server.with_tls(acceptor);
    }
    server.run().await
}
