//! The handful of custom widgets the UI is built from.

use std::time::Duration;

use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CursorIcon, Event, FontId, Frame, ImeEvent, Key,
    Layout, Margin, Rect, Response, RichText, Role, Sense, Stroke, StrokeKind, TextStyle, Ui,
    WidgetInfo,
};
use zeroize::Zeroize;

use crate::secret::SecretString;
use crate::theme::Palette;

pub const FIELD_HEIGHT: f32 = 36.0;
const RADIUS: u8 = 6;

/// A top navigation tab: text with an accent underline when active.
pub fn nav_tab(ui: &mut Ui, p: &Palette, label: &str, active: bool) -> Response {
    let font = FontId::proportional(14.0);
    let text_width = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font.clone(), p.text)
        .size()
        .x;
    let (rect, response) = ui.allocate_exact_size(vec2(text_width + 32.0, 44.0), Sense::click());
    response.widget_info(|| WidgetInfo::selected(Role::Button, true, active, label));

    let color = if active {
        p.accent
    } else if response.hovered() {
        p.text
    } else {
        p.text_weak
    };
    if response.hovered() && !active {
        ui.painter().rect_filled(rect, 0, p.bg_tertiary);
    }
    ui.painter()
        .text(rect.center(), Align2::CENTER_CENTER, label, font, color);
    if active {
        let line = Rect::from_min_max(pos2(rect.left(), rect.bottom() - 2.0), rect.max);
        ui.painter().rect_filled(line, 0, p.accent);
    }
    response.on_hover_cursor(CursorIcon::PointingHand)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Neutral,
    Success,
    Error,
}

/// The rounded status badge on the right of the navigation bar. A long
/// message is cut off here; the full text is on hover and on the Tools page.
pub fn status_pill(ui: &mut Ui, p: &Palette, kind: StatusKind, text: &str, max_width: f32) {
    let (fill, color) = match kind {
        StatusKind::Neutral => (p.bg_tertiary, p.text_weak),
        StatusKind::Success => (p.success.gamma_multiply(0.15), p.success),
        StatusKind::Error => (p.danger.gamma_multiply(0.15), p.danger),
    };
    let mut job = egui::text::LayoutJob::simple_singleline(
        text.to_owned(),
        FontId::proportional(12.5),
        color,
    );
    job.wrap = egui::text::TextWrapping::truncate_at_width((max_width - 24.0).max(20.0));
    let galley = ui.painter().layout_job(job);
    let (rect, response) =
        ui.allocate_exact_size(vec2(galley.size().x + 24.0, 24.0), Sense::hover());
    ui.painter().rect_filled(rect, 12, fill);
    ui.painter().galley(
        pos2(rect.left() + 12.0, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    response.widget_info(|| WidgetInfo::labeled(Role::Status, true, text));
    response.on_hover_text(text);
}

pub fn page_title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(21.0).strong());
    ui.add_space(2.0);
}

pub fn page_hint(ui: &mut Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).size(12.5).color(p.text_weak));
    ui.add_space(6.0);
}

pub fn form_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(13.5).strong());
}

pub fn small_text(ui: &mut Ui, text: &str, color: Color32) {
    ui.label(RichText::new(text).size(12.0).color(color));
}

/// A text field with buttons on its right. Returns the field's response and
/// the index of the clicked button, if any.
pub fn input_row<R>(
    ui: &mut Ui,
    buttons: &[&str],
    field: impl FnOnce(&mut Ui) -> R,
) -> (R, Option<usize>) {
    let mut clicked = None;
    let inner = ui.allocate_ui_with_layout(
        vec2(ui.available_width(), FIELD_HEIGHT),
        Layout::right_to_left(Align::Center),
        |ui| {
            for (index, label) in buttons.iter().enumerate().rev() {
                if secondary_button(ui, label).clicked() {
                    clicked = Some(index);
                }
            }
            field(ui)
        },
    );
    (inner.inner, clicked)
}

/// A single-line path field filling the remaining width.
pub fn path_field(ui: &mut Ui, value: &mut String, hint: &str) -> Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(ui.available_width())
            .min_size(vec2(0.0, FIELD_HEIGHT))
            .margin(Margin::symmetric(10, 9)),
    )
}

pub fn secondary_button(ui: &mut Ui, label: &str) -> Response {
    ui.add(egui::Button::new(label).min_size(vec2(0.0, FIELD_HEIGHT)))
        .on_hover_cursor(CursorIcon::PointingHand)
}

/// A full-width call-to-action button. While `busy`, it shows a spinner and
/// `busy_label` instead and cannot be clicked.
pub fn primary_button(
    ui: &mut Ui,
    p: &Palette,
    label: &str,
    fill: Color32,
    hover_fill: Color32,
    busy: Option<&str>,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 42.0), Sense::click());
    response.widget_info(|| WidgetInfo::labeled(Role::Button, ui.is_enabled(), label));
    let enabled = ui.is_enabled() && busy.is_none();
    let fill = if enabled && response.hovered() {
        hover_fill
    } else {
        fill
    };
    let painter = ui.painter();
    painter.rect_filled(rect, RADIUS, fill);
    if response.has_focus() {
        painter.rect_stroke(
            rect.expand(2.0),
            RADIUS + 2,
            Stroke::new(2.0, fill),
            StrokeKind::Outside,
        );
    }
    let font = FontId::proportional(14.5);
    match busy {
        Some(busy_label) => {
            let galley = painter.layout_no_wrap(busy_label.to_owned(), font, p.on_accent);
            let total = 18.0 + 10.0 + galley.size().x;
            let left = rect.center().x - total / 2.0;
            spinner(ui, pos2(left + 9.0, rect.center().y), 8.0, p.on_accent);
            ui.painter().galley(
                pos2(left + 28.0, rect.center().y - galley.size().y / 2.0),
                galley,
                p.on_accent,
            );
        }
        None => {
            painter.text(
                rect.center(),
                Align2::CENTER_CENTER,
                label,
                font,
                p.on_accent,
            );
        }
    }
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A rotating arc. Repaints at a modest rate rather than every display frame:
/// the CPU is busy with Argon2id while this is on screen.
pub fn spinner(ui: &Ui, center: egui::Pos2, radius: f32, color: Color32) {
    let time = ui.input(|i| i.time);
    let start = (time * 5.0) % std::f64::consts::TAU;
    let points: Vec<_> = (0..=24)
        .map(|i| {
            let angle = start + (i as f64 / 24.0) * std::f64::consts::PI * 1.5;
            pos2(
                center.x + radius * angle.cos() as f32,
                center.y + radius * angle.sin() as f32,
            )
        })
        .collect();
    ui.painter()
        .add(egui::Shape::line(points, Stroke::new(2.0, color)));
    ui.ctx().request_repaint_after(Duration::from_millis(33));
}

/// A card-style row with a label, a hint, and an on/off switch on the right.
/// The whole row toggles.
pub fn switch_row(ui: &mut Ui, p: &Palette, on: &mut bool, label: &str, hint: &str) -> Response {
    const SWITCH_W: f32 = 38.0;
    const SWITCH_H: f32 = 22.0;
    const PAD_X: f32 = 12.0;
    const PAD_Y: f32 = 8.0;

    let width = ui.available_width();
    let text_width = (width - 2.0 * PAD_X - SWITCH_W - 14.0).max(50.0);
    let label_galley = ui.painter().layout(
        label.to_owned(),
        FontId::proportional(14.0),
        p.text,
        text_width,
    );
    let hint_galley = ui.painter().layout(
        hint.to_owned(),
        FontId::proportional(12.0),
        p.text_weak,
        text_width,
    );
    let height = (PAD_Y * 2.0 + label_galley.size().y + 2.0 + hint_galley.size().y).max(46.0);
    let (rect, mut response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response.widget_info(|| WidgetInfo::selected(Role::CheckBox, ui.is_enabled(), *on, label));

    let stroke = if *on {
        p.accent
    } else if response.hovered() {
        p.text_weak
    } else {
        p.border
    };
    let painter = ui.painter();
    painter.rect(
        rect,
        RADIUS,
        p.bg_primary,
        Stroke::new(1.0, stroke),
        StrokeKind::Inside,
    );

    let text_top = rect.center().y - (label_galley.size().y + 2.0 + hint_galley.size().y) / 2.0;
    let label_height = label_galley.size().y;
    painter.galley(pos2(rect.left() + PAD_X, text_top), label_galley, p.text);
    painter.galley(
        pos2(rect.left() + PAD_X, text_top + label_height + 2.0),
        hint_galley,
        p.text_weak,
    );

    let track = Rect::from_center_size(
        pos2(rect.right() - PAD_X - SWITCH_W / 2.0, rect.center().y),
        vec2(SWITCH_W, SWITCH_H),
    );
    let (track_fill, track_stroke, knob) = if *on {
        (p.accent, p.accent, Color32::WHITE)
    } else {
        (p.bg_tertiary, p.border, p.text_weak)
    };
    painter.rect(
        track,
        11,
        track_fill,
        Stroke::new(1.0, track_stroke),
        StrokeKind::Inside,
    );
    let knob_x = if *on {
        track.right() - 11.0
    } else {
        track.left() + 11.0
    };
    painter.circle_filled(pos2(knob_x, track.center().y), 8.0, knob);
    if response.has_focus() {
        painter.rect_stroke(
            track.expand(2.0),
            13,
            Stroke::new(2.0, p.accent),
            StrokeKind::Outside,
        );
    }
    response.on_hover_cursor(CursorIcon::PointingHand)
}

/// The "Advanced options" divider: a caret and label between two rules, with
/// a badge showing how many options inside are on.
pub fn disclosure(ui: &mut Ui, p: &Palette, open: &mut bool, label: &str, badge: Option<&str>) {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 26.0), Sense::click());
    if response.clicked() {
        *open = !*open;
    }
    response.widget_info(|| WidgetInfo::selected(Role::Button, true, *open, label));
    let color = if *open || response.hovered() {
        p.text
    } else {
        p.text_weak
    };
    let painter = ui.painter();
    let label_font = FontId::proportional(12.5);
    let badge_font = FontId::proportional(11.0);
    let label_galley = painter.layout_no_wrap(label.to_owned(), label_font, color);
    let badge_galley = badge.map(|b| painter.layout_no_wrap(b.to_owned(), badge_font, p.accent));
    let badge_width = badge_galley
        .as_ref()
        .map_or(0.0, |g| g.size().x + 16.0 + 8.0);
    let group_width = 8.0 + 8.0 + label_galley.size().x + badge_width;
    let left = rect.center().x - group_width / 2.0;
    let cy = rect.center().y;

    let rule = Stroke::new(1.0, p.border);
    painter.line_segment([pos2(rect.left(), cy), pos2(left - 10.0, cy)], rule);
    painter.line_segment(
        [pos2(left + group_width + 10.0, cy), pos2(rect.right(), cy)],
        rule,
    );

    let caret = if *open {
        vec![
            pos2(left, cy - 2.5),
            pos2(left + 8.0, cy - 2.5),
            pos2(left + 4.0, cy + 2.5),
        ]
    } else {
        vec![
            pos2(left + 1.5, cy - 4.0),
            pos2(left + 6.5, cy),
            pos2(left + 1.5, cy + 4.0),
        ]
    };
    painter.add(egui::Shape::convex_polygon(caret, color, Stroke::NONE));

    let label_x = left + 16.0;
    let label_width = label_galley.size().x;
    painter.galley(
        pos2(label_x, cy - label_galley.size().y / 2.0),
        label_galley,
        color,
    );

    if let Some(galley) = badge_galley {
        let badge_rect = Rect::from_min_size(
            pos2(label_x + label_width + 8.0, cy - 9.0),
            vec2(galley.size().x + 16.0, 18.0),
        );
        painter.rect_filled(badge_rect, 9, p.accent.gamma_multiply(0.15));
        painter.galley(
            pos2(badge_rect.left() + 8.0, cy - galley.size().y / 2.0),
            galley,
            p.accent,
        );
    }
    response.on_hover_cursor(CursorIcon::PointingHand);
}

/// Thin coloured bar for the password-strength score (0 to 100).
pub fn strength_bar(ui: &mut Ui, p: &Palette, score: u32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 3.0), Sense::hover());
    ui.painter().rect_filled(rect, 2, p.bg_tertiary);
    let filled = Rect::from_min_size(rect.min, vec2(rect.width() * score as f32 / 100.0, 3.0));
    ui.painter().rect_filled(filled, 2, color);
}

pub fn card<R>(ui: &mut Ui, p: &Palette, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(p.bg_primary)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(RADIUS)
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Monospace box for the last operation's result. Selectable, so a path can
/// be copied out of it.
pub fn result_box(ui: &mut Ui, p: &Palette, text: &str) {
    Frame::new()
        .fill(p.bg_primary)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(RADIUS)
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(50.0);
            ui.label(RichText::new(text).monospace().color(p.text_weak));
        });
}

pub struct SecretResponse {
    pub submitted: bool,
}

/// A password field that edits a [`SecretString`] in place.
///
/// egui's own `TextEdit` copies its text into undo snapshots and selection
/// reports every frame. This field keeps no copy: typed characters go
/// straight into the wiped buffer. In exchange it is append-only - typing
/// adds at the end, Backspace removes the last character, Ctrl+Backspace
/// clears it - which is all a password field needs.
pub fn secret_field(
    ui: &mut Ui,
    p: &Palette,
    id_salt: &str,
    label: &str,
    secret: &mut SecretString,
    visible: bool,
) -> SecretResponse {
    let id = ui.make_persistent_id(id_salt);
    let (_, rect) = ui.allocate_space(vec2(ui.available_width(), FIELD_HEIGHT));
    let response = ui.interact(rect, id, Sense::click());
    let enabled = ui.is_enabled();
    if enabled {
        ui.memory_mut(|m| m.interested_in_focus(id, ui.layer_id()));
    }
    if response.clicked() {
        response.request_focus();
    }
    response.widget_info(|| WidgetInfo::labeled(Role::PasswordInput, enabled, label));

    let focused = enabled && response.has_focus();
    let mut submitted = false;
    if focused {
        ui.input(|input| {
            for event in &input.events {
                match event {
                    Event::Text(text) | Event::Paste(text) | Event::Ime(ImeEvent::Commit(text)) => {
                        let mut bytes = [0u8; 4];
                        for c in text.chars().filter(|c| !c.is_control()) {
                            secret.push_str(c.encode_utf8(&mut bytes));
                        }
                        bytes.zeroize();
                    }
                    Event::Key {
                        key: Key::Backspace,
                        pressed: true,
                        modifiers,
                        ..
                    } => {
                        if modifiers.command || modifiers.ctrl || modifiers.alt {
                            secret.clear();
                        } else {
                            secret.pop();
                        }
                    }
                    Event::Key {
                        key: Key::Enter,
                        pressed: true,
                        ..
                    } => submitted = true,
                    _ => {}
                }
            }
        });
        if ui.input(|i| i.key_pressed(Key::Escape)) {
            response.surrender_focus();
        }
    }

    let stroke = if focused {
        p.accent
    } else if response.hovered() && enabled {
        p.text_weak
    } else {
        p.border
    };
    let painter = ui.painter();
    painter.rect(
        rect,
        RADIUS,
        p.bg_primary,
        Stroke::new(1.0, stroke),
        StrokeKind::Inside,
    );

    let inner = rect.shrink2(vec2(10.0, 0.0));
    let font = TextStyle::Body.resolve(ui.style());
    // When shown, the text has to be laid out like any other; that copy lives
    // in egui's text cache until it is evicted. Hidden, only dots are laid out.
    let shown = if visible {
        secret.to_unprotected_string()
    } else {
        "\u{2022}".repeat(secret.char_count())
    };
    let galley = painter.layout_no_wrap(shown, font, p.text);
    let overflow = (galley.size().x + 3.0 - inner.width()).max(0.0);
    let text_pos = pos2(
        inner.left() - overflow,
        rect.center().y - galley.size().y / 2.0,
    );
    let caret_x = text_pos.x + galley.size().x + 1.0;
    let clipped = painter.with_clip_rect(rect.shrink(1.0));
    clipped.galley(text_pos, galley, p.text);
    if focused {
        clipped.line_segment(
            [
                pos2(caret_x, rect.center().y - 9.0),
                pos2(caret_x, rect.center().y + 9.0),
            ],
            Stroke::new(1.5, p.text),
        );
    }
    if enabled {
        response.on_hover_cursor(CursorIcon::Text);
    }
    SecretResponse { submitted }
}
