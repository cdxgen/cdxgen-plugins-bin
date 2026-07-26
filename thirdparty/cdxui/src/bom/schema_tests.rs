#[cfg(test)]
mod tests {
    use crate::bom::schema::*;

    #[test]
    fn test_deserialize_full_bom() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:test-123",
            "version": 1,
            "metadata": {
                "timestamp": "2025-01-01T00:00:00Z",
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "cdxgen",
                            "version": "12.6.0"
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "bom-ref": "root-app",
                    "name": "my-app",
                    "version": "1.0.0",
                    "purl": "pkg:generic/my-app@1.0.0",
                    "licenses": [
                        {"license": {"id": "MIT", "name": "MIT License"}},
                        {"expression": "MIT OR Apache-2.0"}
                    ]
                }
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:npm/express@4.18.0",
                    "name": "express",
                    "version": "4.18.0",
                    "purl": "pkg:npm/express@4.18.0",
                    "description": "Fast, unopinionated web framework",
                    "scope": "required",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "hashes": [
                        {"alg": "SHA-256", "content": "abc123"}
                    ],
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://expressjs.com"
                        }
                    ]
                },
                {
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto:tls-cert",
                    "name": "TLS Server Certificate",
                    "cryptoProperties": {
                        "assetType": "certificate",
                        "certificateProperties": {
                            "subjectName": "CN=example.com",
                            "issuerName": "CN=Let's Encrypt",
                            "notValidBefore": "2025-01-01T00:00:00Z",
                            "notValidAfter": "2025-12-31T23:59:59Z",
                            "certificateFormat": "X.509"
                        }
                    }
                },
                {
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto:aes-256-gcm",
                    "name": "AES-256-GCM",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "AES",
                            "mode": "GCM",
                            "cryptoFunctions": ["encrypt", "decrypt"],
                            "classicalSecurityLevel": 256
                        }
                    }
                },
                {
                    "type": "container",
                    "bom-ref": "docker:alpine",
                    "name": "alpine",
                    "version": "3.19",
                    "purl": "pkg:docker/alpine@3.19"
                },
                {
                    "type": "data",
                    "bom-ref": "data:model-weights",
                    "name": "model-weights",
                    "data": [
                        {
                            "name": "weights.bin",
                            "classification": "proprietary"
                        }
                    ]
                }
            ],
            "services": [
                {
                    "bom-ref": "svc:api-gateway",
                    "name": "api-gateway",
                    "endpoints": ["https://api.example.com", "https://api.internal.example.com"],
                    "authenticated": true,
                    "x-trust-boundary": true,
                    "description": "API Gateway service",
                    "data": [
                        {
                            "classification": "PII",
                            "flow": "bidirectional"
                        }
                    ]
                }
            ],
            "dependencies": [
                {
                    "ref": "pkg:npm/express@4.18.0",
                    "dependsOn": []
                },
                {
                    "ref": "crypto:tls-cert",
                    "dependsOn": ["pkg:npm/express@4.18.0"]
                },
                {
                    "ref": "crypto:aes-256-gcm",
                    "dependsOn": ["pkg:npm/express@4.18.0"]
                }
            ],
            "formulation": [
                {
                    "name": "ci-cd-pipeline",
                    "description": "CI/CD build pipeline",
                    "workflows": [
                        {
                            "uid": "wf-1",
                            "name": "build-and-test",
                            "description": "Build and test workflow",
                            "tasks": [
                                {
                                    "uid": "task-1",
                                    "name": "compile",
                                    "description": "Compile source code",
                                    "steps": [
                                        {
                                            "name": "cargo build",
                                            "description": "Build Rust project",
                                            "commands": [
                                                {"executed": "cargo build --release --target x86_64-unknown-linux-gnu"}
                                            ]
                                        }
                                    ]
                                },
                                {
                                    "uid": "task-2",
                                    "name": "test",
                                    "description": "Run tests",
                                    "steps": [
                                        {
                                            "name": "cargo test",
                                            "commands": [
                                                {"executed": "cargo test"}
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "taskDependencies": [
                                {"ref": "task-2"}
                            ]
                        }
                    ]
                }
            ],
            "vulnerabilities": [
                {
                    "bom-ref": "vuln-1",
                    "id": "CVE-2025-0001",
                    "description": "Sample vulnerability",
                    "ratings": [
                        {
                            "score": 7.5,
                            "severity": "high",
                            "method": "CVSSv3"
                        }
                    ],
                    "affects": [
                        {
                            "ref": "pkg:npm/express@4.18.0"
                        }
                    ]
                }
            ]
        }"#;

        let bom: Bom = serde_json::from_str(json).unwrap();

        assert_eq!(bom.bom_format.as_deref(), Some("CycloneDX"));
        assert_eq!(bom.spec_version.as_deref(), Some("1.7"));
        assert_eq!(bom.serial_number.as_deref(), Some("urn:uuid:test-123"));
        assert_eq!(bom.version, Some(1));

        let components = bom.components.unwrap();
        assert_eq!(components.len(), 5);

        let library = &components[0];
        assert_eq!(library.component_type, "library");
        assert_eq!(library.name.as_deref(), Some("express"));
        assert_eq!(library.purl.as_deref(), Some("pkg:npm/express@4.18.0"));

        let crypto_cert = &components[1];
        assert_eq!(crypto_cert.component_type, "cryptographic-asset");
        let cert_props = crypto_cert.crypto_properties.as_ref().unwrap();
        assert_eq!(cert_props.asset_type.as_deref(), Some("certificate"));
        assert_eq!(
            cert_props.certificate_properties.as_ref().unwrap().subject_name.as_deref(),
            Some("CN=example.com")
        );

        let crypto_algo = &components[2];
        let algo_props = crypto_algo.crypto_properties.as_ref().unwrap();
        assert_eq!(algo_props.asset_type.as_deref(), Some("algorithm"));
        assert_eq!(
            algo_props.algorithm_properties.as_ref().unwrap().primitive.as_deref(),
            Some("AES")
        );
        assert_eq!(
            algo_props.algorithm_properties.as_ref().unwrap().mode.as_deref(),
            Some("GCM")
        );

        let services = bom.services.unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name.as_deref(), Some("api-gateway"));
        assert_eq!(services[0].authenticated, Some(true));
        assert_eq!(services[0].x_trust_boundary, Some(true));
        assert_eq!(
            services[0].endpoints.as_ref().unwrap(),
            &["https://api.example.com", "https://api.internal.example.com"]
        );

        let deps = bom.dependencies.unwrap();
        assert_eq!(deps.len(), 3);

        let formulas = bom.formulation.unwrap();
        assert_eq!(formulas.len(), 1);
        let wf = &formulas[0].workflows.as_ref().unwrap()[0];
        assert_eq!(wf.name.as_deref(), Some("build-and-test"));
        let tasks = wf.tasks.as_ref().unwrap();
        assert_eq!(tasks.len(), 2);

        let vulns = bom.vulnerabilities.unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id.as_deref(), Some("CVE-2025-0001"));
        let rating = &vulns[0].ratings.as_ref().unwrap()[0];
        assert_eq!(rating.severity.as_deref(), Some("high"));
    }

    #[test]
    fn test_deserialize_minimal_bom() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1
        }"#;

        let bom: Bom = serde_json::from_str(json).unwrap();
        assert_eq!(bom.bom_format.as_deref(), Some("CycloneDX"));
        assert_eq!(bom.spec_version.as_deref(), Some("1.4"));
        assert!(bom.components.is_none());
        assert!(bom.services.is_none());
        assert!(bom.dependencies.is_none());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let bom = Bom {
            bom_format: Some("CycloneDX".into()),
            spec_version: Some("1.7".into()),
            serial_number: Some("urn:uuid:test".into()),
            version: Some(1),
            metadata: None,
            components: Some(vec![Component {
                component_type: "library".into(),
                bom_ref: Some("pkg:npm/test@1.0.0".into()),
                name: Some("test".into()),
                version: Some("1.0.0".into()),
                purl: Some("pkg:npm/test@1.0.0".into()),
                ..Default::default()
            }]),
            services: None,
            dependencies: None,
            formulation: None,
            compositions: None,
            annotations: None,
            vulnerabilities: None,
            definitions: None,
            extra: Default::default(),
        };

        let json = serde_json::to_string(&bom).unwrap();
        let parsed: Bom = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.bom_format.as_deref(), Some("CycloneDX"));
        assert_eq!(parsed.components.unwrap()[0].name.as_deref(), Some("test"));
    }

    #[test]
    fn test_deserialize_spec_2_0() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "2.0",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test"
                }
            ]
        }"#;

        let bom: Bom = serde_json::from_str(json).unwrap();
        assert_eq!(bom.spec_version.as_deref(), Some("2.0"));
    }

    #[test]
    fn test_deserialize_depscan_vdr_vuln() {
        // Mirrors the shape dep-scan emits: source, cwes, analysis, references,
        // published/updated, and the depscan:* properties.
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "vulnerabilities": [
                {
                    "bom-ref": "CVE-2024-38355/pkg:npm/socket.io@3.1.2",
                    "id": "CVE-2024-38355",
                    "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-38355"},
                    "references": [
                        {"id": "GHSA-25hc-qcg6-38wj", "source": {"name": "GitHub Advisory"}}
                    ],
                    "description": "socket.io has an unhandled error event",
                    "detail": "Impact: A crafted packet can trigger an unhandled error event.",
                    "recommendation": "Update to version 4.6.2.",
                    "ratings": [{"method": "CVSSv4", "severity": "medium", "score": 6.9, "vector": "CVSS:4.0/AV:N"}],
                    "cwes": [20, 754],
                    "affects": [
                        {"ref": "pkg:npm/socket.io@3.1.2", "versions": [
                            {"range": "vers:npm/>=3.0.0|<4.6.2", "status": "affected"},
                            {"version": "4.6.2", "status": "unaffected"}
                        ]}
                    ],
                    "advisories": [{"title": "GHSA", "url": "https://example.com"}],
                    "analysis": {"state": "exploitable", "detail": "See exploit"},
                    "published": "2024-06-19T15:04:41",
                    "updated": "2024-11-18T16:26:46",
                    "properties": [
                        {"name": "depscan:prioritized", "value": "false"},
                        {"name": "depscan:insights", "value": "Reachable\\nUsed in 3 locations"}
                    ]
                }
            ]
        }"#;

        let bom: Bom = serde_json::from_str(json).unwrap();
        let vulns = bom.vulnerabilities.unwrap();
        assert_eq!(vulns.len(), 1);
        let v = &vulns[0];
        assert_eq!(v.id.as_deref(), Some("CVE-2024-38355"));
        assert_eq!(v.source.as_ref().unwrap().name.as_deref(), Some("NVD"));
        assert_eq!(v.references.as_ref().unwrap()[0].id.as_deref(), Some("GHSA-25hc-qcg6-38wj"));
        assert_eq!(v.cwes.as_ref().unwrap(), &vec![20, 754]);
        let analysis = v.analysis.as_ref().unwrap();
        assert_eq!(analysis.state.as_deref(), Some("exploitable"));
        assert_eq!(analysis.detail.as_deref(), Some("See exploit"));
        assert_eq!(v.published.as_deref(), Some("2024-06-19T15:04:41"));
        assert_eq!(v.updated.as_deref(), Some("2024-11-18T16:26:46"));
        // fix (unaffected) version
        let versions = &v.affects.as_ref().unwrap()[0].versions.as_ref().unwrap();
        assert_eq!(versions[1].version.as_deref(), Some("4.6.2"));
        assert_eq!(versions[1].status.as_deref(), Some("unaffected"));
    }
}
