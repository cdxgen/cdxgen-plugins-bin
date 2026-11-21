//! The second level: `deep_note!` reaches the crate root through `outer`.

macro_rules! deep_note {
    () => {
        $crate::helper::enc(11)
    };
}
