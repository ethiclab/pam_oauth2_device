use std::process::Command;

pub fn create_local_user(
    username: &str, 
    group: Option<&str>
) -> Result<(), Box<dyn std::error::Error>> {
    if username == "root" {
        return Err("Invalid username".into());
    }

    if users::get_user_by_name(username).is_some() {
        return Ok(());
    }

    let status = Command::new("/usr/sbin/useradd")
        .arg(username)
        .arg("-m")
        .arg("-s")
        .arg("/bin/bash")
        .status()?;

    if status.success() {
        log::info!("User '{}' created successfully", username);

        if let Some(group_name) = group {
            let status = Command::new("/usr/sbin/usermod")
                .arg("-aG")
                .arg(group_name)
                .arg(username)
                .status()?;

            if status.success() {
                log::info!("User '{}' added to '{}' group successfully", username, group_name);
            } else {
                log::error!(
                    "Failed to add user '{}' to group '{}': {:?}", 
                    username, group_name, status
                );
                return Err(format!(
                    "Failed to add user '{}' to group '{}'", 
                    username, group_name
                ).into());
            }
        }

        Ok(())
    } else {
        Err(format!("Failed to create user: {}", status).into())
    }
}
