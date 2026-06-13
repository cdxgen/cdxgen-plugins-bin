use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub tab_active_bg: Color,
    pub tab_active_fg: Color,
    pub tab_inactive_bg: Color,
    pub tab_inactive_fg: Color,
    pub search_bg: Color,
    pub search_fg: Color,
    pub table_header_bg: Color,
    pub table_header_fg: Color,
    pub table_row_fg: Color,
    pub table_selected_bg: Color,
    pub table_selected_fg: Color,
    pub table_alt_bg: Color,
    pub detail_bg: Color,
    pub detail_fg: Color,
    pub status_bg: Color,
    pub status_fg: Color,
    pub help_bg: Color,
    pub help_fg: Color,
    pub accent: Color,
    pub warn: Color,
    pub error: Color,
    pub crypto_accent: Color,
    pub tab_bg: [Color; 7],
}

impl Theme {
    pub fn dark() -> Self {
        let accent = Color::Rgb(100, 180, 255);
        Self {
            bg: Color::Rgb(18, 18, 18),
            fg: Color::Rgb(220, 220, 220),
            tab_active_bg: Color::Rgb(55, 55, 55),
            tab_active_fg: Color::Rgb(255, 255, 255),
            tab_inactive_bg: Color::Rgb(30, 30, 30),
            tab_inactive_fg: Color::Rgb(150, 150, 150),
            search_bg: Color::Rgb(40, 40, 40),
            search_fg: Color::Rgb(200, 200, 200),
            table_header_bg: Color::Rgb(45, 45, 45),
            table_header_fg: Color::Rgb(200, 200, 200),
            table_row_fg: Color::Rgb(210, 210, 210),
            table_selected_bg: Color::Rgb(70, 70, 120),
            table_selected_fg: Color::Rgb(255, 255, 255),
            table_alt_bg: Color::Rgb(24, 24, 24),
            detail_bg: Color::Rgb(25, 25, 35),
            detail_fg: Color::Rgb(200, 200, 220),
            status_bg: Color::Rgb(40, 40, 60),
            status_fg: Color::Rgb(180, 180, 200),
            help_bg: Color::Rgb(30, 30, 50),
            help_fg: Color::Rgb(180, 180, 200),
            accent,
            warn: Color::Rgb(255, 200, 100),
            error: Color::Rgb(255, 100, 100),
            crypto_accent: Color::Rgb(180, 140, 255),
            tab_bg: [
                Color::Rgb(20, 22, 18), // Logs - dark green tint
                Color::Rgb(18, 18, 18), // Summary - neutral
                Color::Rgb(18, 18, 24), // Components - blue tint
                Color::Rgb(22, 18, 24), // Crypto - purple tint
                Color::Rgb(18, 24, 20), // Services - green tint
                Color::Rgb(24, 20, 18), // Formulation - warm tint
                Color::Rgb(20, 20, 22), // Dependencies - cool tint
            ],
        }
    }

    pub fn light() -> Self {
        let accent = Color::Rgb(50, 120, 220);
        Self {
            bg: Color::Rgb(245, 245, 245),
            fg: Color::Rgb(30, 30, 30),
            tab_active_bg: Color::Rgb(200, 200, 200),
            tab_active_fg: Color::Rgb(0, 0, 0),
            tab_inactive_bg: Color::Rgb(225, 225, 225),
            tab_inactive_fg: Color::Rgb(100, 100, 100),
            search_bg: Color::Rgb(215, 215, 215),
            search_fg: Color::Rgb(50, 50, 50),
            table_header_bg: Color::Rgb(210, 210, 210),
            table_header_fg: Color::Rgb(50, 50, 50),
            table_row_fg: Color::Rgb(40, 40, 40),
            table_selected_bg: Color::Rgb(120, 140, 200),
            table_selected_fg: Color::Rgb(255, 255, 255),
            table_alt_bg: Color::Rgb(238, 238, 238),
            detail_bg: Color::Rgb(235, 235, 245),
            detail_fg: Color::Rgb(30, 30, 50),
            status_bg: Color::Rgb(220, 220, 240),
            status_fg: Color::Rgb(60, 60, 80),
            help_bg: Color::Rgb(230, 230, 245),
            help_fg: Color::Rgb(60, 60, 80),
            accent,
            warn: Color::Rgb(200, 140, 0),
            error: Color::Rgb(200, 50, 50),
            crypto_accent: Color::Rgb(130, 80, 200),
            tab_bg: [
                Color::Rgb(240, 248, 240), // Logs
                Color::Rgb(245, 245, 245), // Summary
                Color::Rgb(240, 240, 250), // Components
                Color::Rgb(248, 240, 248), // Crypto
                Color::Rgb(240, 250, 242), // Services
                Color::Rgb(250, 245, 240), // Formulation
                Color::Rgb(242, 242, 248), // Dependencies
            ],
        }
    }

    pub fn tab_index(tab: crate::app::Tab) -> usize {
        use crate::app::Tab;
        match tab {
            Tab::Logs => 0,
            Tab::Summary => 1,
            Tab::Components => 2,
            Tab::Crypto => 3,
            Tab::Services => 4,
            Tab::Formulation => 5,
            Tab::Dependencies => 6,
        }
    }

    pub fn tab_active_style(&self) -> Style {
        Style::default()
            .fg(self.tab_active_fg)
            .bg(self.tab_active_bg)
    }

    pub fn tab_inactive_style(&self) -> Style {
        Style::default()
            .fg(self.tab_inactive_fg)
            .bg(self.tab_inactive_bg)
    }

    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(self.table_header_fg)
            .bg(self.table_header_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn selected_style(&self) -> Style {
        Style::default()
            .fg(self.table_selected_fg)
            .bg(self.table_selected_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn crypto_style(&self) -> Style {
        Style::default().fg(self.crypto_accent)
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}
