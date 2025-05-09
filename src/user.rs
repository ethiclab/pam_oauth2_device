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

    let output = Command::new("useradd")
        .arg(username)
        .arg("-m")
        .arg("-s")
        .arg("/bin/bash")
        .status()?;

    if output.success() {
        log::info!("User '{}' created successfully", username);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to create user: {}", stderr).into())
    }
}
