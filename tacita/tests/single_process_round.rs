use tacita::{
    client::Client,
    committee::CommitteeMember,
    config::{ProtocolConfig, RoundConfig},
    simulator::{
        SingleProcessSimulator, ToyMklhtsBackend, ToyMklhtsConfig, ToyPlaintext, ToySteBackend,
        ToySteConfig,
    },
};

#[test]
fn single_process_round_succeeds_end_to_end() {
    let protocol = ProtocolConfig {
        registration_epoch: 1,
        threshold: 2,
        expected_clients: 3,
        committee_size: 4,
    };
    let round = RoundConfig {
        round_id: 5,
        threshold: 2,
        expected_clients: 3,
        expected_committee_members: 4,
    };

    let simulator = SingleProcessSimulator::new(
        protocol,
        ToySteBackend::new(ToySteConfig {
            committee_size: 4,
            slot_count: 2,
            threshold: 2,
            seed: 2026,
            max_discrete_log: 32,
        })
        .unwrap(),
        ToyMklhtsBackend::new(ToyMklhtsConfig {
            expected_clients: 3,
            seed: 3291,
        })
        .unwrap(),
    );

    let clients = vec![Client::new(0), Client::new(1), Client::new(2)];
    let committee = vec![
        CommitteeMember::new(0),
        CommitteeMember::new(1),
        CommitteeMember::new(2),
        CommitteeMember::new(3),
    ];
    let offline = simulator.prepare_offline_phase(&clients, &committee).unwrap();

    let client_inputs = vec![
        (clients[0].clone(), ToyPlaintext::new(vec![2, 1])),
        (clients[1].clone(), ToyPlaintext::new(vec![1, 2])),
        (clients[2].clone(), ToyPlaintext::new(vec![4, 3])),
    ];

    let outcome = simulator
        .simulate_online_round(&round, &offline, &client_inputs, &committee[..2])
        .unwrap();

    assert_eq!(outcome.result.aggregate_plaintext, ToyPlaintext::new(vec![7, 6]));
    assert_eq!(
        outcome
            .transcript
            .events
            .iter()
            .map(|event| event.stage.clone())
            .collect::<Vec<_>>(),
        vec![
            "online-config".to_string(),
            "client-encrypt-and-sign".to_string(),
            "server-aggregate".to_string(),
            "committee-verify-and-partial-decrypt".to_string(),
            "server-finalize".to_string(),
        ]
    );
}
