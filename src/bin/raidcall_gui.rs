//! Native GUI for the supported Windows and Linux platforms.
use eframe::egui;
mod gui_i18n;
use gui_i18n::Language;
use raidcall_history_decryptor::{decrypt_file, DecryptOptions, DecryptReport};
#[cfg(target_os = "windows")]
use raidcall_history_decryptor::discovery::{discover_windows_accounts, RaidCallAccount};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

enum Event {
    Progress(u64, u64),
    Complete(Result<DecryptReport, String>),
}

struct DecryptApp {
    input: String,
    account: String,
    output: String,
    save_next_to_source: bool,
    overwrite: bool,
    verify_header: bool,
    running: bool,
    awaiting_confirmation: bool,
    progress: f32,
    status: String,
    language: Language,
    receiver: Option<Receiver<Event>>,
    #[cfg(target_os = "windows")]
    discovered_accounts: Vec<RaidCallAccount>,
    #[cfg(target_os = "windows")]
    selected_account: Option<usize>,
}

impl DecryptApp {
    fn new(storage: Option<&dyn eframe::Storage>, ctx: &egui::Context) -> Self {
        let language = storage.and_then(|s| s.get_string("language"))
            .map(|s| Language::from_code(&s)).unwrap_or_else(Language::from_system);
        gui_i18n::configure_fonts(ctx);
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(language.tr("title").to_owned()));
        let mut app = Self {
            input: String::new(), account: String::new(), output: String::new(),
            save_next_to_source: true, overwrite: false, verify_header: true,
            running: false, awaiting_confirmation: false, progress: 0.0,
            status: language.tr("ready").to_owned(), language,
            receiver: None,
            #[cfg(target_os = "windows")]
            discovered_accounts: Vec::new(),
            #[cfg(target_os = "windows")]
            selected_account: None,
        };
        #[cfg(target_os = "windows")]
        app.refresh_accounts();
        app
    }

    #[cfg(target_os = "windows")]
    fn refresh_accounts(&mut self) {
        self.selected_account = None;
        match discover_windows_accounts() {
            Ok(accounts) => {
                self.status = if accounts.is_empty() {
                    self.language.tr("account_not_found").into()
                } else {
                    format!("{}: {}", self.language.tr("account_count"), accounts.len())
                };
                self.discovered_accounts = accounts;
            }
            Err(error) => {
                self.discovered_accounts.clear();
                self.status = format!("{}: {error}", self.language.tr("account_error"));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn choose_account(&mut self, index: usize) {
        if let Some(found) = self.discovered_accounts.get(index).cloned() {
            self.pick_input(found.dat_path);
            self.account = found.account;
            self.selected_account = Some(index);
            self.status = self.language.tr("account_chosen").into();
        }
    }

    fn pick_input(&mut self, path: PathBuf) {
        #[cfg(target_os = "windows")]
        { self.selected_account = None; }
        self.account = path.file_stem()
            .map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        self.output = path.with_extension("sqlite3").to_string_lossy().into_owned();
        self.input = path.to_string_lossy().into_owned();
    }

    fn start(&mut self) {
        if self.running { return; }
        let options = DecryptOptions {
            input: PathBuf::from(self.input.trim()),
            account: self.account.trim().to_owned(),
            output: if self.save_next_to_source {
                PathBuf::from(self.input.trim()).with_extension("sqlite3")
            } else {
                PathBuf::from(self.output.trim())
            },
            overwrite: self.overwrite,
            verify_header: self.verify_header,
        };
        if options.input.as_os_str().is_empty()
            || options.output.as_os_str().is_empty()
            || options.account.is_empty()
        {
            self.status = self.language.tr("missing_fields").into();
            return;
        }
        if !options.input.is_file() {
            self.status = self.language.tr("missing_input").into();
            return;
        }
        if options.output.exists() && !options.overwrite {
            self.status = self.language.tr("exists").into();
            return;
        }
        if options.output.exists() && self.overwrite && !self.awaiting_confirmation {
            self.awaiting_confirmation = true;
            return;
        }
        self.awaiting_confirmation = false;
        self.running = true;
        self.progress = 0.0;
        self.status = self.language.tr("working").into();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        thread::spawn(move || {
            let mut last_percent = None;
            let result = decrypt_file(&options, |done, total| {
                let percent = if total == 0 { 100 } else { done.saturating_mul(100) / total };
                if last_percent != Some(percent) || done == total {
                    let _ = tx.send(Event::Progress(done, total));
                    last_percent = Some(percent);
                }
            });
            let _ = tx.send(Event::Complete(result));
        });
    }

    fn receive_events(&mut self) {
        let mut complete = false;
        if let Some(rx) = &self.receiver {
            for event in rx.try_iter() {
                match event {
                    Event::Progress(done, total) => {
                        self.progress = if total == 0 { 1.0 } else {
                            (done as f32 / total as f32).clamp(0.0, 1.0)
                        };
                    }
                    Event::Complete(Ok(report)) => {
                        self.progress = 1.0;
                        self.status = format!(
                            "{}: {} pages ({} bytes) -> {}",
                            self.language.tr("done"), report.pages, report.bytes, report.output.display()
                        );
                        complete = true;
                    }
                    Event::Complete(Err(e)) => {
                        self.status = format!("{}: {e}", self.language.tr("error"));
                        complete = true;
                    }
                }
            }
        }
        if complete {
            self.running = false;
            self.receiver = None;
        }
    }
}

impl eframe::App for DecryptApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        storage.set_string("language", self.language.code().to_owned());
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_events();
        if self.running { ctx.request_repaint_after(Duration::from_millis(100)); }
        let language_before = self.language;
        egui::TopBottomPanel::top("display_preferences")
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(self.language.tr("language"));
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(match self.language {
                            Language::TraditionalChinese => self.language.tr("language_chinese"),
                            Language::English => self.language.tr("language_english"),
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.language, Language::TraditionalChinese,
                                language_before.tr("language_chinese"),
                            );
                            ui.selectable_value(
                                &mut self.language, Language::English,
                                language_before.tr("language_english"),
                            );
                        });
                });
            });
        if self.language != language_before {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(
                self.language.tr("title").to_owned(),
            ));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Keep controls accessible at small window sizes. Vertical scrolling
            // reaches every form row; horizontal scrolling handles unbreakable
            // paths and unusually narrow viewports without hiding controls.
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                ui.set_min_width(ui.available_width().max(1.0));
                ui.heading(self.language.tr("title"));
                ui.label(self.language.tr("subtitle"));
                ui.separator();

                #[cfg(target_os = "windows")]
                ui.add_enabled_ui(!self.running, |ui| {
                    ui.label(self.language.tr("accounts"));
                    let label = self.selected_account
                        .and_then(|i| self.discovered_accounts.get(i))
                        .map(|a| a.account.clone())
                        .unwrap_or_else(|| self.language.tr("choose_account").to_owned());
                    let mut chosen = None;
                    ui.horizontal_wrapped(|ui| {
                        egui::ComboBox::from_id_salt("discovered_raidcall_accounts")
                            .selected_text(label)
                            .width((ui.available_width() - 10.0).clamp(110.0, 350.0))
                            .show_ui(ui, |ui| {
                                for (i, account) in self.discovered_accounts.iter().enumerate() {
                                    if ui.selectable_label(self.selected_account == Some(i), &account.account).clicked() {
                                        chosen = Some(i);
                                    }
                                }
                            });
                        if ui.button(self.language.tr("rescan")).clicked() {
                            self.refresh_accounts();
                        }
                    });
                    if let Some(i) = chosen { self.choose_account(i); }
                    ui.small(if self.discovered_accounts.is_empty() {
                        self.language.tr("no_accounts")
                    } else {
                        self.language.tr("found_accounts")
                    });
                    ui.add_space(6.0);
                });

                ui.add_enabled_ui(!self.running, |ui| {
                    ui.label(self.language.tr("input"));
                    ui.add_sized(
                        [ui.available_width().max(40.0), 27.0],
                        egui::TextEdit::singleline(&mut self.input)
                            .hint_text(self.language.tr("input_hint")),
                    );
                    if ui.button(self.language.tr("browse")).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("RaidCall data", &["dat"]).pick_file() {
                            self.pick_input(path);
                        }
                    }
                    ui.add_space(8.0);

                    ui.label(self.language.tr("account"));
                    ui.add_sized([ui.available_width().max(40.0), 27.0],
                        egui::TextEdit::singleline(&mut self.account));
                    ui.small(self.language.tr("special"));
                    ui.add_space(8.0);

                    ui.label(self.language.tr("output"));
                    ui.radio_value(&mut self.save_next_to_source, true, self.language.tr("beside"));
                    ui.radio_value(&mut self.save_next_to_source, false, self.language.tr("custom"));
                    if self.save_next_to_source {
                        ui.add(egui::Label::new(format!("{}: {}",
                            self.language.tr("output"),
                            PathBuf::from(self.input.trim()).with_extension("sqlite3").display()
                        )).wrap());
                    } else {
                        ui.add_sized([ui.available_width().max(40.0), 27.0],
                            egui::TextEdit::singleline(&mut self.output)
                                .hint_text(self.language.tr("output_hint")));
                        if ui.button(self.language.tr("save_as")).clicked() {
                            let default_name = Path::new(&self.output).file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "decrypted.sqlite3".into());
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("SQLite database", &["sqlite3", "sqlite"])
                                .set_file_name(&default_name).save_file() {
                                self.output = path.to_string_lossy().into_owned();
                            }
                        }
                    }
                    ui.add_space(8.0);
                    ui.checkbox(&mut self.overwrite, self.language.tr("overwrite"));
                    ui.checkbox(&mut self.verify_header, self.language.tr("verify"));
                    ui.add_space(8.0);
                    if ui.button(self.language.tr("decrypt")).clicked() { self.start(); }
                });

                ui.separator();
                ui.add(egui::ProgressBar::new(self.progress)
                    .desired_width(ui.available_width().max(40.0))
                    .show_percentage());
                ui.add(egui::Label::new(&self.status).wrap());
                ui.add_space(4.0);
                ui.small(self.language.tr("footer"));
            });
        });

        if self.awaiting_confirmation {
            egui::Window::new(self.language.tr("confirm"))
                .collapsible(false).resizable(true)
                .default_width(350.0)
                .show(ctx, |ui| {
                    ui.label(self.language.tr("confirm_text"));
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(self.language.tr("cancel")).clicked() {
                            self.awaiting_confirmation = false;
                        }
                        if ui.button(self.language.tr("replace")).clicked() {
                            self.start();
                        }
                    });
                });
        }
    }
}

// Renderer configuration is kept separate from the GUI/decryption code.
mod gui_render_backend;

fn main() -> eframe::Result<()> {
    let result = eframe::run_native(
        Language::from_system().tr("title"),
        gui_render_backend::create_native_options(),
        Box::new(|cc| Ok(Box::new(DecryptApp::new(cc.storage, &cc.egui_ctx)))),
    );
    #[cfg(target_os = "windows")]
    if let Err(error) = &result {
        eprintln!("RaidCall GUI renderer initialization failed: {error}");
        eprintln!(
            "The GUI prefers Vulkan, then D3D12/WARP, then compatible modern OpenGL. \
             OpenGL 1.1 cannot run egui. Ensure your VM has Vulkan or D3D12/WARP \
             if there is no newer GL driver. The rc-dat-decrypt.exe CLI needs no GPU."
        );
    }
    result
}
