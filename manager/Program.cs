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
    private readonly ToolStripTextBox address = new() { Text = "http://127.0.0.1:8081/", AutoSize = false, Width = 255 };
    private readonly ToolStripDropDownButton service = new("Локальная служба");
    private readonly ToolStripStatusLabel status = new();
    private readonly ToolStripButton connect = new("Подключиться");
    private readonly System.Windows.Forms.Timer poll = new() { Interval = 3000 };
    private bool operating;

    public Manager()
    {
        Text = "Hookbox Manager";
        MinimumSize = new Size(760, 520);
        Size = new Size(1120, 800);
        StartPosition = FormStartPosition.CenterScreen;
        var bar = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(8, 4, 8, 4) };
        bar.Items.AddRange([new ToolStripLabel("Панель"), address, connect, new ToolStripSeparator(), service]);
        foreach (var (label, op) in new[] { ("Запустить", "start"), ("Остановить", "stop"), ("Перезапустить", "restart") })
            service.DropDownItems.Add(label, null, async (_, _) => await ChangeService(op));
        var info = new StatusStrip();
        info.Items.Add(status);
        Controls.Add(view);
        Controls.Add(bar);
        Controls.Add(info);
        connect.Enabled = false;
        connect.Click += (_, _) => Navigate();
        address.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter && connect.Enabled) { e.SuppressKeyPress = true; Navigate(); } };
        Shown += async (_, _) => await InitializeBrowser();
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
            var profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Hookbox", "WebView2");
            var env = await CoreWebView2Environment.CreateAsync(userDataFolder: profile);
            await view.EnsureCoreWebView2Async(env);
            view.CoreWebView2.Settings.AreHostObjectsAllowed = false;
            view.CoreWebView2.Settings.IsWebMessageEnabled = false;
            view.CoreWebView2.NavigationStarting += (_, e) => e.Cancel = !Uri.TryCreate(e.Uri, UriKind.Absolute, out var u) || !Allowed(u);
            view.CoreWebView2.NewWindowRequested += (_, e) => e.Handled = true;
            connect.Enabled = true;
            Navigate();
        }
        catch (Exception exc)
        {
            MessageBox.Show(this, "Не удалось открыть WebView2. Проверь установку Microsoft Edge WebView2 Runtime.\n" + exc.Message, Text);
        }
    }

    private void Navigate()
    {
        if (!Uri.TryCreate(address.Text.Trim(), UriKind.Absolute, out var u) || !Allowed(u))
        {
            MessageBox.Show(this, "Введи HTTPS-адрес панели или HTTP-адрес на localhost.", Text);
            return;
        }
        view.CoreWebView2.Navigate(u.AbsoluteUri);
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
            service.Enabled = false;
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
