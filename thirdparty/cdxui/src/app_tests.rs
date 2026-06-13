#[cfg(test)]
mod tests {
    use crate::app::{App, InputMode, Tab};
    use crate::bom::store::BomStore;

    fn make_test_app() -> App {
        let store = BomStore::new();
        App::new(store)
    }

    #[test]
    fn test_tab_navigation_next() {
        assert_eq!(Tab::Logs.next(), Tab::Summary);
        assert_eq!(Tab::Summary.next(), Tab::Components);
        assert_eq!(Tab::Components.next(), Tab::Dependencies);
        assert_eq!(Tab::Dependencies.next(), Tab::Crypto);
        assert_eq!(Tab::Crypto.next(), Tab::Services);
        assert_eq!(Tab::Services.next(), Tab::Formulation);
        assert_eq!(Tab::Formulation.next(), Tab::Logs);
    }

    #[test]
    fn test_tab_navigation_prev() {
        assert_eq!(Tab::Logs.prev(), Tab::Formulation);
        assert_eq!(Tab::Formulation.prev(), Tab::Services);
        assert_eq!(Tab::Services.prev(), Tab::Crypto);
        assert_eq!(Tab::Crypto.prev(), Tab::Dependencies);
        assert_eq!(Tab::Dependencies.prev(), Tab::Components);
        assert_eq!(Tab::Components.prev(), Tab::Summary);
        assert_eq!(Tab::Summary.prev(), Tab::Logs);
    }

    #[test]
    fn test_tab_labels() {
        assert_eq!(Tab::Summary.label(), "Summary");
        assert_eq!(Tab::Components.label(), "Components");
        assert_eq!(Tab::Crypto.label(), "Crypto");
        assert_eq!(Tab::Services.label(), "Services");
        assert_eq!(Tab::Formulation.label(), "Formulation");
        assert_eq!(Tab::Dependencies.label(), "Dependencies");
    }

    #[test]
    fn test_app_initial_state() {
        let app = make_test_app();
        assert_eq!(app.current_tab, Tab::Summary);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(!app.should_quit);
        assert!(!app.detail_open);
        assert_eq!(app.search_input, "");
        assert_eq!(app.table_selected, 0);
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn test_search_mode_transition() {
        let mut app = make_test_app();
        app.set_search();
        assert_eq!(app.input_mode, InputMode::Search);
        app.clear_search();
        assert_eq!(app.input_mode, InputMode::Normal);
        assert_eq!(app.search_input, "");
    }

    #[test]
    fn test_move_selection_up_down() {
        let mut app = make_test_app();
        assert_eq!(app.table_selected, 0);
        app.move_selection_down();
        assert_eq!(app.table_selected, 0);
        app.move_selection_up();
        assert_eq!(app.table_selected, 0);
    }

    #[test]
    fn test_toggle_detail() {
        let mut app = make_test_app();
        assert!(!app.detail_open);
        app.toggle_detail();
        assert!(app.detail_open);
        app.toggle_detail();
        assert!(!app.detail_open);
    }

    #[test]
    fn test_tab_switching_resets_state() {
        let mut app = make_test_app();
        app.table_selected = 5;
        app.scroll_offset = 10;
        app.detail_open = true;

        app.switch_tab(Tab::Components);

        assert_eq!(app.scroll_offset, 0);
        assert_eq!(app.table_selected, 0);
        assert_eq!(app.detail_scroll, 0);
    }
}
