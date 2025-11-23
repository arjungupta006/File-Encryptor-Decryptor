#include <gtk/gtk.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "filecrypt.h"  

typedef struct {
    GtkWidget *entry_password;
    GtkWidget *entry_input;
    GtkWidget *entry_output;
    GtkWidget *progress_bar;
    GtkWidget *status_label;
    int encrypt_mode;
} AppWidgets;

void set_status(AppWidgets *app, const char *text) {
    gtk_label_set_text(GTK_LABEL(app->status_label), text);
    while (gtk_events_pending()) gtk_main_iteration();
}

void *run_crypto(void *arg) {
    AppWidgets *app = (AppWidgets *)arg;
    const char *in_file = gtk_entry_get_text(GTK_ENTRY(app->entry_input));
    const char *out_file = gtk_entry_get_text(GTK_ENTRY(app->entry_output));
    const char *password = gtk_entry_get_text(GTK_ENTRY(app->entry_password));

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.1);
    set_status(app, "Processing...");

    int success = 0;
    if (app->encrypt_mode)
        success = encrypt_file(in_file, out_file, password);
    else
        success = decrypt_file(in_file, out_file, password);

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 1.0);

    if (success)
        set_status(app, app->encrypt_mode ? "✅ Encryption successful" : "✅ Decryption successful");
    else
        set_status(app, "❌ Operation failed – check password or file.");

    return NULL;
}

void on_browse_input(GtkButton *button, AppWidgets *app) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Input File",
        NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(app->entry_input), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

void on_browse_output(GtkButton *button, AppWidgets *app) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Output File",
        NULL, GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(app->entry_output), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

void on_run_clicked(GtkButton *button, AppWidgets *app) {
    const char *pwd = gtk_entry_get_text(GTK_ENTRY(app->entry_password));
    if (strlen(pwd) < 4) {
        set_status(app, "Password must be at least 4 characters!");
        return;
    }
    set_status(app, app->encrypt_mode ? "Encrypting..." : "Decrypting...");
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress_bar));

    pthread_t thread;
    pthread_create(&thread, NULL, run_crypto, app);
    pthread_detach(thread);
}

void on_mode_toggle(GtkSwitch *sw, gboolean state, AppWidgets *app) {
    app->encrypt_mode = state;
    const char *mode = app->encrypt_mode ? "Mode: Encrypt" : "Mode: Decrypt";
    set_status(app, mode);
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "FileCrypt GUI — AES-256 GCM");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);
    gtk_container_set_border_width(GTK_CONTAINER(window), 15);

    AppWidgets *app = g_slice_new(AppWidgets);
    app->encrypt_mode = 1;

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_add(GTK_CONTAINER(window), grid);

    GtkWidget *label_mode = gtk_label_new("Mode:");
    GtkWidget *switch_mode = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(switch_mode), TRUE);
    gtk_grid_attach(GTK_GRID(grid), label_mode, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), switch_mode, 1, 0, 1, 1);

    GtkWidget *label_pass = gtk_label_new("Password:");
    app->entry_password = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(app->entry_password), FALSE);
    gtk_grid_attach(GTK_GRID(grid), label_pass, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->entry_password, 1, 1, 2, 1);

    GtkWidget *label_in = gtk_label_new("Input File:");
    app->entry_input = gtk_entry_new();
    GtkWidget *btn_in = gtk_button_new_with_label("Browse");
    gtk_grid_attach(GTK_GRID(grid), label_in, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->entry_input, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_in, 2, 2, 1, 1);

    GtkWidget *label_out = gtk_label_new("Output File:");
    app->entry_output = gtk_entry_new();
    GtkWidget *btn_out = gtk_button_new_with_label("Browse");
    gtk_grid_attach(GTK_GRID(grid), label_out, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->entry_output, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_out, 2, 3, 1, 1);

    GtkWidget *btn_run = gtk_button_new_with_label("Run");
    gtk_grid_attach(GTK_GRID(grid), btn_run, 1, 4, 1, 1);

    app->progress_bar = gtk_progress_bar_new();
    gtk_grid_attach(GTK_GRID(grid), app->progress_bar, 0, 5, 3, 1);

    app->status_label = gtk_label_new("Ready.");
    gtk_widget_override_color(app->status_label, GTK_STATE_FLAG_NORMAL, &(GdkRGBA){0.0, 1.0, 0.0, 1.0});
    gtk_grid_attach(GTK_GRID(grid), app->status_label, 0, 6, 3, 1);

    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(switch_mode, "state-set", G_CALLBACK(on_mode_toggle), app);
    g_signal_connect(btn_in, "clicked", G_CALLBACK(on_browse_input), app);
    g_signal_connect(btn_out, "clicked", G_CALLBACK(on_browse_output), app);
    g_signal_connect(btn_run, "clicked", G_CALLBACK(on_run_clicked), app);

    gtk_widget_show_all(window);
    gtk_main();
    g_slice_free(AppWidgets, app);
    return 0;
}
