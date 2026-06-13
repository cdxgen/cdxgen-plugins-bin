use crate::bom::store::BomStore;
use crate::bom::store::SortField;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Logs,
    Summary,
    Components,
    Crypto,
    Services,
    Formulation,
    Dependencies,
}

impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Logs,
        Tab::Summary,
        Tab::Components,
        Tab::Dependencies,
        Tab::Crypto,
        Tab::Services,
        Tab::Formulation,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Logs => "Logs",
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
pub enum PanelFocus {
    Main,
    Thoughts,
    Stdout,
}

#[derive(Debug, Clone)]
pub struct App {
    pub store: BomStore,
    pub current_tab: Tab,
    pub input_mode: InputMode,
    pub search_input: String,
    pub should_quit: bool,
    pub detail_open: bool,
    pub scroll_offset: u16,
    pub table_selected: usize,
    pub detail_scroll: u16,
    pub component_type_filter: Option<String>,
    pub type_filter_selected: usize,
    pub last_item_count: usize,
    pub dep_expanded: std::collections::HashSet<String>,
    pub dep_tree_refs: Vec<String>,
    pub generating: bool,
    pub generation_done: bool,
    pub output_path: Option<std::path::PathBuf>,
    pub thought_text: String,
    pub thoughts_collapsed: bool,
    pub switch_timer: Option<std::time::Instant>,
    pub focused_panel: PanelFocus,
    pub thought_scroll: u16,
    pub stdout_scroll: u16,
    pub panel_areas: std::vec::Vec<(PanelFocus, ratatui::layout::Rect)>,
    pub tab_positions: std::vec::Vec<(Tab, u16, u16)>,
    pub component_header_y: u16,
    pub component_header_positions: std::vec::Vec<(SortField, u16, u16)>,
    pub dep_tree_area: Option<ratatui::layout::Rect>,
    pub visible_rows: u16,
    pub selection_start_row: Option<usize>,
    pub selection_end_row: Option<usize>,
    pub last_click_time: Option<std::time::Instant>,
    pub last_click_row: usize,
}

impl App {
    pub fn new(store: BomStore) -> Self {
        Self {
            store,
            current_tab: Tab::Summary,
            input_mode: InputMode::Normal,
            search_input: String::new(),
            should_quit: false,
            detail_open: false,
            scroll_offset: 0,
            table_selected: 0,
            detail_scroll: 0,
            component_type_filter: None,
            type_filter_selected: 0,
            last_item_count: 0,
            dep_expanded: std::collections::HashSet::new(),
            dep_tree_refs: Vec::new(),
            generating: false,
            generation_done: false,
            output_path: None,
            thought_text: String::new(),
            thoughts_collapsed: false,
            switch_timer: None,
            focused_panel: PanelFocus::Main,
            thought_scroll: 0,
            stdout_scroll: 0,
            panel_areas: Vec::new(),
            tab_positions: Vec::new(),
            component_header_y: 0,
            component_header_positions: Vec::new(),
            dep_tree_area: None,
            visible_rows: 15,
            selection_start_row: None,
            selection_end_row: None,
            last_click_time: None,
            last_click_row: 0,
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
        self.clamp_scroll();
    }

    pub fn apply_search(&mut self) {
        self.store.search_components(&self.search_input);
        self.scroll_offset = 0;
        self.table_selected = 0;
        self.clamp_scroll();
    }

    pub fn tab_label(&self, tab: Tab) -> String {
        let base = tab.label();
        match tab {
            Tab::Components => format!("{} ({})", base, self.store.filtered_components_count()),
            Tab::Crypto => format!("{} ({})", base, self.store.total_crypto),
            Tab::Services => format!("{} ({})", base, self.store.filtered_services_count()),
            Tab::Formulation => {
                let count = self.store.formula_count();
                format!("{} ({})", base, count)
            }
            Tab::Dependencies => format!("{} ({})", base, self.store.total_dependencies),
            Tab::Logs => format!("{} ({})", base, self.last_item_count),
            Tab::Summary => format!("{} ({} files)", base, self.store.file_count()),
        }
    }

    pub fn current_list_len(&self) -> usize {
        match self.current_tab {
            Tab::Components | Tab::Crypto => self.store.filtered_components_count(),
            Tab::Services => self.store.filtered_services_count(),
            _ => {
                if self.last_item_count > 0 {
                    self.last_item_count
                } else {
                    match self.current_tab {
                        Tab::Formulation => self.store.formula_count(),
                        Tab::Dependencies => self.store.total_dependencies,
                        Tab::Summary => 1,
                        _ => 0,
                    }
                }
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

    pub fn switch_tab(&mut self, tab: Tab) {
        if self.current_tab != tab {
            self.detail_open = false;
        }
        self.current_tab = tab;
        self.scroll_offset = 0;
        self.table_selected = 0;
        self.detail_scroll = 0;
        self.last_item_count = 0;
    }

    pub fn toggle_dep_expand(&mut self) {
        let ref_field = self.dep_tree_refs
            .get(self.table_selected)
            .cloned()
            .unwrap_or_default();
        if ref_field.is_empty() {
            return;
        }
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

    pub fn toggle_thoughts_collapse(&mut self) {
        self.thoughts_collapsed = !self.thoughts_collapsed;
    }

    pub fn clamp_scroll(&mut self) {
        let total = self.current_list_len() as u16;
        let v = self.visible_rows.max(1);
        let max = if total > v { total - v } else { 0 };
        self.scroll_offset = self.scroll_offset.min(max);
    }

    pub fn selected_rows(&self) -> Option<(usize, usize)> {
        match (self.selection_start_row, self.selection_end_row) {
            (Some(start), Some(end)) if start <= end => Some((start, end)),
            (Some(start), Some(end)) => Some((end, start)),
            _ => None,
        }
    }

    pub fn clear_selection(&mut self) {
        self.selection_start_row = None;
        self.selection_end_row = None;
    }
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
