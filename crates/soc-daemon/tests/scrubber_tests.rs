use soc_daemon::pipeline::PiiScrubber;

#[test]
fn test_pii_and_token_redaction() {
    let scrubber = PiiScrubber::new();

    // 1. Home directory masking
    let path = "/home/purpleronin/.ssh/authorized_keys";
    let scrubbed_path = scrubber.scrub_text(path);
    assert_eq!(scrubbed_path, "/home/<user>/.ssh/authorized_keys");

    // 2. Bearer token stripping
    let auth_header = "Authorization: Bearer sk-ant-api03-abcdef1234567890xyz";
    let scrubbed_auth = scrubber.scrub_text(auth_header);
    assert!(scrubbed_auth.contains("Bearer=[REDACTED_TOKEN]"));
    assert!(!scrubbed_auth.contains("sk-ant-api03"));

    // 3. Password field stripping
    let config = "db_connection: password=SuperSecretPassword123!";
    let scrubbed_config = scrubber.scrub_text(config);
    assert!(scrubbed_config.contains("password=[REDACTED_SECRET]"));
    assert!(!scrubbed_config.contains("SuperSecretPassword123!"));

    // 4. Private key stripping
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----";
    let scrubbed_pem = scrubber.scrub_text(pem);
    assert_eq!(scrubbed_pem, "[REDACTED_PRIVATE_KEY]");

    // 5. Salted IP pseudonymization
    let ip = "192.168.1.50";
    let hashed1 = scrubber.hash_ip(ip);
    let hashed2 = scrubber.hash_ip(ip);
    assert_eq!(hashed1, hashed2); // Consistent within node session
    assert!(hashed1.starts_with("ip-"));
    assert!(!hashed1.contains("192.168"));
}
