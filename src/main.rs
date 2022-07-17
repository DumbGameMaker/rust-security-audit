
use std::{self, io::Write};

use clap::{Arg, Command};
use regex::Regex;

fn main() {
    let matches = Command::new("Audit")
        .version("0.0.1b1")
        .author("Syrx <opal.js@icloud.com>")
        .about("Scans your system for security best practices")
        .arg_required_else_help(true)
        .arg(Arg::with_name("Everything")
            .short('A')
            .long("all")
            .help("Run all scans and checks"))
        .arg(Arg::with_name("ssh")
            .short('s')
            .long("ssh")
            .help("Check for ssh configuration"))
        .arg(Arg::with_name("logins")
            .short('l')
            .long("logins")
            .help("Scan for malicious ssh login attempts"))
        .arg(Arg::with_name("interactive")
            .short('i')
            .long("interactive")
            .help("Run in interactive mode"))
        .arg(Arg::with_name("verbose")
            .short('v')
            .long("verbose")
            .help("Be verbose"))
        .get_matches();

    if!matches.args_present() {
        println!("You must specify one of: Asl");
        std::process::exit(1);
    }
    parse_args(matches);
}
   



fn parse_args(matches: clap::ArgMatches) {
    if matches.is_present("interactive") {
        println!("Running in interactive mode");
    }
    if matches.is_present("Everything") {
        println!("Running all scans and checks");
    }
    if matches.is_present("ssh") {
        ssh(matches.is_present("verbose"));
    }
    if matches.is_present("logins") {
        logins(matches.is_present("verbose"));
    }

}

fn ssh(verbose: bool) {
    println!("Checking SSH");
    if verbose {
        println!("INFO: Using default SSHD config /etc/ssh/sshd_config");
    }
    let sshd_config = std::fs::read_to_string("/etc/ssh/sshd_config").unwrap();
    let port = Regex::new("[0-9]{2,5}").unwrap().captures(Regex::new("#{0,1}[ ]{0,10}Port .*").unwrap().captures(&sshd_config).unwrap().get(0).unwrap().as_str()).unwrap().get(0).unwrap().as_str();
    
    if verbose {
        println!("INFO: Port is {}", port);
    }
    if port == "22" {
        println!("WARNING: SSH is listening on port 22");
        println!("Fix: Change the line '{}' to 'Port x' where x is a number between 49152 and 65535. Remember this number, and use it when connecting to your device over ssh.", Regex::new("#{0,1}[ ]{0,10}Port .*").unwrap().captures(&sshd_config).unwrap().get(0).unwrap().as_str());
        
    }
    if !sshd_config.contains("PermitRootLogin no") {
        println!("WARNING: SSH may be allowing root login");
        println!("Fix: Change the line '{}' to 'PermitRootLogin no'", Regex::new("#{0,1}[ ]{0,10}PermitRootLogin .*").unwrap().captures(&sshd_config).unwrap().get(0).unwrap().as_str());
    }
    if sshd_config.contains("PasswordAuth yes") {
        println!("WARNING: SSH is allowing password login");
        println!("Fix: Change the line '{}' to 'PasswordAuth no'", Regex::new("#{0,1}[ ]{0,10}PasswordAuth .*").unwrap().captures(&sshd_config).unwrap().get(0).unwrap().as_str());
    }
    if sshd_config.contains("PubkeyAuthentication no") {
        println!("WARNING: SSH is not allowing public key login");
        println!("Fix: Change the line '{}' to 'PubkeyAuthentication yes'. Generate ssh keys with the ssh-keygen tool on the client, and put the public key on the server in ~/.ssh/authorized_keys", Regex::new("#{0,1}[ ]{0,10}PubkeyAuthentication .*").unwrap().captures(&sshd_config).unwrap().get(0).unwrap().as_str());
    }

}

fn logins(verbose: bool){
println!("Checking logins");

    let sysos = String::from_utf8(std::process::Command::new("uname").arg("-v").output().unwrap().stdout).unwrap();
    let mut ssh_path = "";
    if sysos.contains("Darwin"){
        return println!("WARNING! SSH login attempts cannot be detected on Mac OS");
    }
    else if sysos.contains("Ubuntu"){
        ssh_path = "cat /var/log/auth.log | egrep -o '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | sort -t\\n -u";
    }
    else if sysos.contains("CentOS"){
        ssh_path = "cat /var/log/secure | egrep -o '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | sort -t\\n -u";
    }
    else {
        return println!("WARNING! SSH login attempts cannot be detected on this OS at the moment.");
    }

    let login_attempts = String::from_utf8(std::process::Command::new("bash").arg("-c").arg(ssh_path).output().unwrap().stdout).unwrap();
    if(login_attempts.len() > 100) {
        println!("More than 100 separate SSH login attempts have been detected. This is *generally* nothing to worry about, as this is common internet noise. You may want to change your ssh port to something other than 22, or setup Fail2Ban.");
        print!("Would you like to save this information to a file? (y/n)");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim() == "y" {
            let mut file = std::fs::File::create("/tmp/ssh_logins.txt").unwrap();
            file.write_all(login_attempts.as_bytes()).unwrap();
            println!("Saved to /tmp/ssh_logins.txt");
        }
        
    }
}