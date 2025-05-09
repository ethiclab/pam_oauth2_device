use std::process::Command;

pub fn create_local_user(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Sicurezza basilare
    if username == "root" {
        return Err("Invalid username".into());
    }

    // Check if user already exists
    if users::get_user_by_name(username).is_some() {
        return Ok(());
    }

    let status = Command::new("useradd")
        .arg(username)
        .arg("-m")
        .arg("-s")
        .arg("/bin/bash")
        .status()?;

    if status.success() {
        log::info!("User '{}' created successfully", username);
        Ok(())
    } else {
        Err(format!("Failed to create user: {}", status).into())
    }
}
