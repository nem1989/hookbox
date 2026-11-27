using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System.ServiceProcess;

namespace HookboxManager;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new Manager());
    }
}

internal sealed class Manager : Form
{
    private readonly WebView2 view = new() { Dock = DockStyle.Fill };
    private Uri endpoint = new("http://127.0.0.1:8081/");
    private readonly Panel offline = new() { Dock = DockStyle.Fill, BackColor = SystemColors.Window, Visible = false };
    private readonly Label offlineAddress = new() { AutoSize = true, Margin = new Padding(0, 5, 0, 18) };
    private readonly ToolStripMenuItem service = new("Локальная служба");
    private readonly ToolStripMenuItem status = new() { Enabled = false };
    private readonly ToolStripMenuItem changeServer = new("Сменить сервер…") { ShortcutKeys = Keys.Control | Keys.K };
    private readonly System.Windows.Forms.Timer poll = new() { Interval = 3000 };
    private bool operating;

    public Manager()
    {
        Text = "Hookbox Manager";
        MinimumSize = new Size(760, 520);
        Size = new Size(1120, 800);
        StartPosition = FormStartPosition.CenterScreen;
        var menu = new MenuStrip { BackColor = SystemColors.Window };
        var connection = new ToolStripMenuItem("Подключение");
        connection.DropDownItems.Add(changeServer);
        changeServer.Click += (_, _) => ChooseServer();
        connection.DropDownItems.Add("Повторить подключение", null, (_, _) => Navigate());
        foreach (var (label, op) in new[] { ("Запустить", "start"), ("Остановить", "stop"), ("Перезапустить", "restart") })
            service.DropDownItems.Add(label, null, async (_, _) => await ChangeService(op));
        service.DropDownItems.Add(new ToolStripSeparator());
        service.DropDownItems.Add(status);
        menu.Items.AddRange([connection, service]);
        MainMenuStrip = menu;
        var message = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        message.Controls.Add(new Label { Text = "Сервер недоступен", AutoSize = true, Font = new Font("Segoe UI", 19), Margin = Padding.Empty });
        message.Controls.Add(offlineAddress);
        var retry = new Button { AutoSize = true, Text = "Повторить подключение" };
        retry.Click += (_, _) => Navigate();
        var choose = new Button { AutoSize = true, Text = "Сменить сервер…" };
        choose.Click += (_, _) => ChooseServer();
        var actions = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty };
        actions.Controls.AddRange([retry, choose]);
        message.Controls.Add(actions);
        var center = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 1 };
        center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        center.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        message.Anchor = AnchorStyles.None;
        center.Controls.Add(message);
        offline.Controls.Add(center);
        Controls.Add(view);
        Controls.Add(offline);
        Controls.Add(menu);
        Load += async (_, _) => await InitializeBrowser();
        poll.Tick += (_, _) => RefreshService();
        FormClosed += (_, _) => poll.Dispose();
        RefreshService();
        poll.Start();
    }

    private static bool Allowed(Uri uri) => uri.IsAbsoluteUri && uri.UserInfo.Length == 0 &&
        (uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback));

    private async Task InitializeBrowser()
    {
        try
        {
            if (File.Exists(Path.Combine(AppContext.BaseDirectory, "WebView2Loader.dll")))
                CoreWebView2Environment.SetLoaderDllFolderPath(AppContext.BaseDirectory);
            Console.Error.WriteLine("WebView2 Runtime " + CoreWebView2Environment.GetAvailableBrowserVersionString());
            var profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Hookbox", "WebView2");
            var env = await CoreWebView2Environment.CreateAsync(userDataFolder: profile);
            await view.EnsureCoreWebView2Async(env);
            view.CoreWebView2.Settings.AreHostObjectsAllowed = false;
            view.CoreWebView2.Settings.IsWebMessageEnabled = false;
            view.CoreWebView2.NavigationStarting += (_, e) => e.Cancel = !Uri.TryCreate(e.Uri, UriKind.Absolute, out var u) || !Allowed(u);
            view.CoreWebView2.NewWindowRequested += (_, e) => e.Handled = true;
            view.CoreWebView2.Settings.IsBuiltInErrorPageEnabled = false;
            view.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            view.CoreWebView2.NavigationCompleted += (_, e) =>
            {
                if (e.WebErrorStatus == CoreWebView2WebErrorStatus.OperationCanceled) return;
                offlineAddress.Text = endpoint.GetLeftPart(UriPartial.Authority);
                offline.Visible = !e.IsSuccess;
                view.Visible = e.IsSuccess;
            };
            Navigate();
        }
        catch (Exception exc)
        {
            Console.Error.WriteLine(exc);
            MessageBox.Show(this, "Не удалось открыть WebView2. Проверь установку Microsoft Edge WebView2 Runtime.\n" + exc.Message, Text);
        }
    }

    private void Navigate()
    {
        if (view.CoreWebView2 != null) view.CoreWebView2.Navigate(endpoint.AbsoluteUri);
    }

    private void ChooseServer()
    {
        using var dialog = new Form { Text = "Подключение к серверу", StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(440, 150), FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
        var label = new Label { Text = "Адрес панели управления", Left = 16, Top = 16, AutoSize = true };
        var input = new TextBox { Text = endpoint.AbsoluteUri, Left = 16, Top = 42, Width = 408 };
        var hint = new Label { Left = 16, Top = 72, Width = 410, Height = 25, ForeColor = SystemColors.GrayText };
        var ok = new Button { Text = "Подключиться", Left = 202, Top = 106, Width = 115 };
        var cancel = new Button { Text = "Отмена", Left = 325, Top = 106, Width = 99, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => {
            if (!Uri.TryCreate(input.Text.Trim(), UriKind.Absolute, out var uri) || !Allowed(uri)) {
                hint.Text = "Введите HTTPS-адрес или локальный HTTP-адрес.";
                input.Focus();
                return;
            }
            endpoint = uri;
            dialog.DialogResult = DialogResult.OK;
        };
        dialog.AcceptButton = ok;
        dialog.CancelButton = cancel;
        dialog.Controls.AddRange([label, input, hint, ok, cancel]);
        dialog.Shown += (_, _) => { input.Focus(); input.SelectAll(); };
        if (dialog.ShowDialog(this) == DialogResult.OK) Navigate();
    }

    private void RefreshService()
    {
        if (operating) return;
        try
        {
            using var sc = new ServiceController("Hookbox", ".");
            var state = sc.Status;
            status.Text = "Локальная служба Hookbox · " + state;
            service.Enabled = true;
            service.DropDownItems[0].Enabled = state == ServiceControllerStatus.Stopped;
            service.DropDownItems[1].Enabled = service.DropDownItems[2].Enabled = state == ServiceControllerStatus.Running;
        }
        catch (Exception)
        {
            status.Text = "Локальная служба Hookbox недоступна";
            for (var i = 0; i < 3; i++) service.DropDownItems[i].Enabled = false;
            service.Enabled = true;
        }
    }

    private async Task ChangeService(string op)
    {
        if (operating) return;
        operating = true;
        service.Enabled = false;
        try
        {
            await Task.Run(() =>
            {
                using var sc = new ServiceController("Hookbox", ".");
                var timeout = TimeSpan.FromSeconds(45);
                if (op != "start") { sc.Stop(); sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout); }
                if (op != "stop") { sc.Start(); sc.WaitForStatus(ServiceControllerStatus.Running, timeout); }
            });
        }
        catch (Exception exc) { MessageBox.Show(this, exc.GetBaseException().Message, "Управление локальной службой"); }
        finally { operating = false; if (!IsDisposed) RefreshService(); }
    }
}
