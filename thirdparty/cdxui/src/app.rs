use crate::bom::store::BomStore;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Summary,
    Components,
    Crypto,
    Services,
    Formulation,
    Dependencies,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Summary,
        Tab::Components,
        Tab::Crypto,
        Tab::Services,
        Tab::Formulation,
        Tab::Dependencies,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Summary => "Summary",
            Tab::Components => "Components",
            Tab::Crypto => "Crypto",
            Tab::Services => "Services",
            Tab::Formulation => "Formulation",
            Tab::Dependencies => "Dependencies",
        }
    }

    pub fn next(self) -> Self {
        let idx = Tab::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Tab::ALL[(idx + 1) % Tab::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let idx = Tab::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Tab::ALL[(idx + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Search,
    TypeFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeNav {
    Normal,
    Tree,
}

#[derive(Debug, Clone)]
pub struct App {
    pub store: BomStore,
    pub current_tab: Tab,
    pub input_mode: InputMode,
    pub tree_mode: TreeNav,
    pub search_input: String,
    pub should_quit: bool,
    pub detail_open: bool,
    pub scroll_offset: u16,
    pub table_selected: usize,
    pub detail_scroll: u16,
    pub component_type_filter: Option<String>,
    pub type_filter_selected: usize,
    pub tree_selected: usize,
    pub tree_expanded: std::collections::HashSet<usize>,
    pub show_help: bool,
    pub message: Option<String>,
    pub paths: Vec<PathBuf>,
    pub last_item_count: usize,
    pub dep_expanded: std::collections::HashSet<String>,
    pub summary_dep_selected: usize,
    pub summary_dep_scroll: u16,
}

impl App {
    pub fn new(store: BomStore, paths: Vec<PathBuf>) -> Self {
        Self {
            store,
            current_tab: Tab::Summary,
            input_mode: InputMode::Normal,
            tree_mode: TreeNav::Normal,
            search_input: String::new(),
            should_quit: false,
            detail_open: false,
            scroll_offset: 0,
            table_selected: 0,
            detail_scroll: 0,
            component_type_filter: None,
            type_filter_selected: 0,
            tree_selected: 0,
            tree_expanded: std::collections::HashSet::new(),
            show_help: false,
            message: None,
            paths,
            last_item_count: 0,
            dep_expanded: std::collections::HashSet::new(),
            summary_dep_selected: 0,
            summary_dep_scroll: 0,
        }
    }

    pub fn set_search(&mut self) {
        self.input_mode = InputMode::Search;
    }

    pub fn clear_search(&mut self) {
        self.input_mode = InputMode::Normal;
        self.search_input.clear();
        self.store.search_components("");
        self.scroll_offset = 0;
        self.table_selected = 0;
    }

    pub fn apply_search(&mut self) {
        self.store.search_components(&self.search_input);
        self.scroll_offset = 0;
        self.table_selected = 0;
    }

    pub fn tab_label(&self, tab: Tab) -> String {
        let base = tab.label();
        match tab {
            Tab::Components => format!("{} ({})", base, self.store.filtered_components_count()),
            Tab::Crypto => format!("{} ({})", base, self.store.total_crypto),
            Tab::Services => format!("{} ({})", base, self.store.filtered_services_count()),
            Tab::Formulation => format!("{} ({})", base,
                if self.last_item_count > 0 { self.last_item_count } else { self.store.formula_count() }),
            Tab::Dependencies => format!("{} ({})", base,
                if self.last_item_count > 0 { self.last_item_count } else { self.store.total_dependencies }),
            Tab::Summary => format!("{} ({} files)", base, self.store.file_count()),
        }
    }

    pub fn current_list_len(&self) -> usize {
        if self.last_item_count > 0 {
            self.last_item_count
        } else {
            match self.current_tab {
                Tab::Components | Tab::Crypto => self.store.filtered_components_count(),
                Tab::Services => self.store.filtered_services_count(),
                Tab::Formulation => self.store.formula_count(),
                Tab::Dependencies => self.store.total_dependencies,
                Tab::Summary => 1,
            }
        }
    }

    pub fn move_selection_up(&mut self) {
        let len = self.current_list_len();
        if len == 0 {
            return;
        }
        if self.table_selected > 0 {
            self.table_selected -= 1;
        } else {
            self.table_selected = len.saturating_sub(1);
        }
    }

    pub fn move_selection_down(&mut self) {
        let len = self.current_list_len();
        if len == 0 {
            return;
        }
        if self.table_selected + 1 < len {
            self.table_selected += 1;
        } else {
            self.table_selected = 0;
        }
    }

    pub fn toggle_detail(&mut self) {
        self.detail_open = !self.detail_open;
    }

    pub fn enter_type_filter(&mut self) {
        self.input_mode = InputMode::TypeFilter;
        self.type_filter_selected = 0;
    }

    pub fn exit_type_filter(&mut self, apply: bool) {
        if apply {
            let types = self.store.component_type_counts();
            let filter = types
                .get(self.type_filter_selected)
                .map(|(t, _)| t.clone());
            self.component_type_filter = filter;
            self.store.set_type_filter(self.component_type_filter.clone());
        }
        self.input_mode = InputMode::Normal;
        self.scroll_offset = 0;
        self.table_selected = 0;
    }

    pub fn clear_type_filter(&mut self) {
        self.component_type_filter = None;
        self.store.set_type_filter(None);
        self.scroll_offset = 0;
        self.table_selected = 0;
    }

    pub fn toggle_tree_node(&mut self) {
        if self.tree_expanded.contains(&self.tree_selected) {
            self.tree_expanded.remove(&self.tree_selected);
        } else {
            self.tree_expanded.insert(self.tree_selected);
        }
    }

    pub fn switch_tab(&mut self, tab: Tab) {
        self.current_tab = tab;
        self.scroll_offset = 0;
        self.table_selected = 0;
        self.detail_scroll = 0;
    }

    pub fn toggle_dep_expand(&mut self) {
        let store = &self.store;
        let all = store.all_dependencies();
        let ref_field = if let Some(d) = all.get(self.table_selected) {
            d.ref_field.clone()
        } else {
            return;
        };
        if self.dep_expanded.contains(&ref_field) {
            self.dep_expanded.remove(&ref_field);
        } else {
            self.dep_expanded.insert(ref_field);
        }
    }

    pub fn expand_all_deps(&mut self) {
        for d in self.store.all_dependencies() {
            self.dep_expanded.insert(d.ref_field.clone());
        }
    }

    pub fn collapse_all_deps(&mut self) {
        self.dep_expanded.clear();
    }

    pub fn cycle_sort(&mut self) {
        self.store.cycle_sort();
        self.table_selected = 0;
        self.scroll_offset = 0;
    }
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
