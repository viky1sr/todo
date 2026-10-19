//! Foreground supervisor for a private Kubo daemon, owned by Rust.

use rukubo::Rukubo;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let rukubo = match Rukubo::from_env() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("rukubo: {error}");
            return ExitCode::FAILURE;
        }
    };
    match command.as_str() {
        "status" => match rukubo.status() {
            Ok(status) => {
                println!(
                    "running={} repository={}",
                    status.running, status.repository
                );
                if status.running {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(error) => {
                eprintln!("rukubo: {error}");
                ExitCode::FAILURE
            }
        },
        "run" | "restart" => match if command == "restart" {
            rukubo.restart()
        } else {
            rukubo.start()
        } {
            Ok(status) => {
                println!("private Kubo running from {}", status.repository);
                loop {
                    std::thread::sleep(Duration::from_secs(30));
                    match rukubo.status() {
                        Ok(status) if status.running => {}
                        Ok(_) => {
                            eprintln!("rukubo: managed Kubo stopped");
                            return ExitCode::FAILURE;
                        }
                        Err(error) => {
                            eprintln!("rukubo: {error}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            Err(error) => {
                eprintln!("rukubo: {error}");
                ExitCode::FAILURE
            }
        },
        "stop" => match rukubo.stop() {
            Ok(status) => {
                println!("private Kubo stopped from {}", status.repository);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("rukubo: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: rukubo [run|stop|restart|status]");
            ExitCode::from(2)
        }
    }
}
