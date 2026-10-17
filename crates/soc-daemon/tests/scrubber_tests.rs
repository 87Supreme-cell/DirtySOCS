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

    // 6. AWS Key masking
    let aws_cmd = "aws s3 cp s3://bucket/dump.tar --access-key AKIAIOSFODNN7EXAMPLE";
    let scrubbed_aws = scrubber.scrub_text(aws_cmd);
    assert!(scrubbed_aws.contains("[REDACTED_AWS_KEY]"));
    assert!(!scrubbed_aws.contains("AKIAIOSFODNN7EXAMPLE"));

    // 7. JWT token masking
    let jwt_payload = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let scrubbed_jwt = scrubber.scrub_text(jwt_payload);
    assert!(scrubbed_jwt.contains("[REDACTED_JWT]"));
    assert!(!scrubbed_jwt.contains("eyJhbGciOi"));

    // 8. Inline IP replacement in free-form logs
    let raw_log = "Connection established from 10.0.4.15 to 198.51.100.22 on port 443";
    let scrubbed_log = scrubber.scrub_text(raw_log);
    assert!(!scrubbed_log.contains("10.0.4.15"));
    assert!(!scrubbed_log.contains("198.51.100.22"));
    assert!(scrubbed_log.contains("ip-"));
}
