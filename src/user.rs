use std::process::Command;

pub fn create_local_user(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Sicurezza basilare
    if username == "root" || username.contains(|c: char| !c.is_ascii_alphanumeric()) {
        return Err("Invalid username".into());
    }

    // Check if user already exists
    if users::get_user_by_name(username).is_some() {
        return Ok(());
    }

    // Crea l’utente con shell bash e home dir
    let output = Command::new("useradd")
        .args(["-m", "-s", "/bin/bash", username])
        .output()?;

    if output.status.success() {
        log::info!("User '{}' created successfully", username);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to create user: {}", stderr).into())
    }
}
