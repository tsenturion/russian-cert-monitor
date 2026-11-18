using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.UI;

namespace RussianCertMonitor.Tests;

internal static class MainFormChecks
{
    private static readonly CertificateStoreDescriptor UserRoot = new(StoreLocation.CurrentUser, "Root");
    private static readonly CertificateStoreDescriptor MachineRoot = new(StoreLocation.LocalMachine, "Root");
    private static readonly CertificateStoreDescriptor UserBlocked = new(StoreLocation.CurrentUser, "Disallowed");
    private static readonly CertificateStoreDescriptor MachineBlocked = new(StoreLocation.LocalMachine, "Disallowed");

    public static void Run()
    {
        WindowsChainResult accepted = new(0);
        WindowsChainResult denied = new(0x04000000);
        InventoryCertificate russian = Certificate("rus", "Российский тест", true, false, true, [UserRoot], [1])
            with { Trust = new(denied, accepted) };
        InventoryCertificate possible = Certificate("possible", "Косвенный тест", false, true, false, [MachineRoot], [2]);
        InventoryCertificate historical = Certificate("old", "История", false, false, true, [UserRoot], []);
        InventoryCertificate foreign = Certificate("foreign", "Иностранный блок", false, false, false,
            [MachineRoot, UserBlocked], [3]) with { Trust = new(accepted, accepted) };
        InventoryCertificate machineBlocked = Certificate("machine", "Блок компьютера", false, false, false,
            [UserRoot, MachineBlocked], [4]);
        InventoryCertificate? callback = null;
        int imports = 0;
        CertificateUiActions actions = new(certificate => callback = certificate,
            certificate => callback = certificate,
            certificate => { callback = certificate; return Task.CompletedTask; },
            certificate => { callback = certificate; return Task.CompletedTask; },
            () => { imports++; return Task.CompletedTask; });
        using MainForm form = new(CertificateCatalog.Load(), () => { }, actions);
        form.Show();
        try
        {
            form.ShowSnapshot(new CertificateInventorySnapshot(DateTimeOffset.UtcNow,
                [russian, possible, historical, foreign, machineBlocked],
                [UserRoot, MachineRoot, UserBlocked, MachineBlocked], [], 5));
            TabControl tabs = Controls(form).OfType<TabControl>().Single();
            ListView matches = List(tabs, "Совпадения");
            ListView all = List(tabs, "Все сертификаты");
            ListView blocked = List(tabs, "Чёрный список");
            TextBox search = Controls(form).OfType<TextBox>().Single(box => box.PlaceholderText == "Поиск по сертификатам");
            ComboBox[] filters = Controls(form).OfType<ComboBox>().ToArray();
            ComboBox category = filters.Single(box => box.Items.Contains("Российские"));
            ComboBox scope = filters.Single(box => box.Items.Contains("Пользователь"));
            Button properties = Button(form, "Свойства");
            Button export = Button(form, "Экспорт CER");
            Button add = Button(form, "Добавить в чёрный список");
            Button remove = Button(form, "Убрать из чёрного списка");
            Button import = Button(form, "Импорт CER/CRT");

            Require(matches.Items.Count == 3 && all.Items.Count == 5 && blocked.Items.Count == 2,
                "Текущие вкладки должны показывать совпадения, весь инвентарь и наблюдаемый чёрный список.");
            Require(!properties.Enabled && !export.Enabled && !add.Enabled && !remove.Enabled && import.Enabled,
                "Действия выбранного сертификата требуют выбора, импорт доступен всегда.");
            search.Text = "foreign";
            Require(all.Items.Count == 1 && blocked.Items.Count == 1 && matches.Items.Count == 0,
                "Поиск по идентификатору должен сразу фильтровать текущие вкладки.");
            search.Text = "Disallowed";
            Require(all.Items.Count == 2 && blocked.Items.Count == 2,
                "Поиск должен учитывать путь хранилища.");
            search.Clear();
            category.SelectedIndex = 1;
            Require(matches.Items.Count == 1 && all.Items.Count == 1 && blocked.Items.Count == 0,
                "Категория российских сертификатов должна применяться ко всем текущим вкладкам.");
            category.SelectedIndex = 2;
            Require(matches.Items.Count == 1 && all.Items.Count == 1,
                "Косвенная категория должна показывать нужный сертификат.");
            category.SelectedIndex = 3;
            Require(matches.Items.Count == 2 && all.Items.Count == 2,
                "Фильтр истории должен включать и подтверждённые российские записи.");
            category.SelectedItem = "Российские цепочки ПК без ошибок";
            Require(all.Items.Count == 1 && ReferenceEquals(all.Items[0].Tag, russian)
                && all.Items[0].SubItems[3].Text == denied.StatusText
                && all.Items[0].SubItems[4].Text == accepted.StatusText,
                "Таблица должна показывать независимые результаты проверки цепочки в обеих областях.");
            category.SelectedItem = "Явный запрет только у пользователя";
            Require(all.Items.Count == 1 && ReferenceEquals(all.Items[0].Tag, russian) && blocked.Items.Count == 0,
                "Фильтр запрета должен учитывать результат цепочки, а не присутствие записи в Disallowed.");
            category.SelectedIndex = 3;
            tabs.SelectedTab = tabs.TabPages.Cast<TabPage>().Single(page => page.Text.StartsWith("Все сертификаты"));
            all.Items.Cast<ListViewItem>().Single(item => ((InventoryCertificate)item.Tag!).Metadata.CertificateId == "old").Selected = true;
            Require(!properties.Enabled && !export.Enabled && !add.Enabled && !remove.Enabled,
                "Запись без DER должна оставаться только для чтения.");
            category.SelectedIndex = 0;
            scope.SelectedIndex = 2;
            Require(blocked.Items.Count == 1 && ((InventoryCertificate)blocked.Items[0].Tag!).Metadata.CertificateId == "machine",
                "Область чёрного списка должна учитывать только расположение в Disallowed.");
            scope.SelectedIndex = 1;
            Require(blocked.Items.Count == 1 && ((InventoryCertificate)blocked.Items[0].Tag!).Metadata.CertificateId == "foreign",
                "Пользовательский Disallowed должен включать даже иностранный сертификат.");
            tabs.SelectedTab = tabs.TabPages.Cast<TabPage>().Single(page => page.Text.StartsWith("Чёрный список"));
            blocked.Items[0].Selected = true;
            properties.PerformClick();
            Require(ReferenceEquals(callback, foreign) && remove.Enabled,
                "Действие должно брать сертификат из текущей вкладки.");
            callback = null;
            export.PerformClick();
            Require(ReferenceEquals(callback, foreign), "Экспорт должен брать выбранный сертификат текущей вкладки.");
            callback = null;
            add.PerformClick();
            Require(ReferenceEquals(callback, foreign), "Добавление должно брать выбранный сертификат текущей вкладки.");
            callback = null;
            remove.PerformClick();
            Require(ReferenceEquals(callback, foreign), "Удаление должно брать выбранный сертификат чёрного списка.");
            search.Text = "foreign";
            Require(blocked.SelectedItems.Count == 1
                && ((InventoryCertificate)blocked.SelectedItems[0].Tag!).Metadata.CertificateId == "foreign",
                "Фильтрация должна сохранять выделение, если сертификат остаётся видимым.");
            search.Clear();
            tabs.SelectedTab = tabs.TabPages.Cast<TabPage>().Single(page => page.Text.StartsWith("Справочник"));
            Require(!properties.Enabled && !export.Enabled && !add.Enabled && !remove.Enabled,
                "Выбор на другой вкладке не должен оставлять действия доступными в справочнике.");
            import.PerformClick();
            Require(imports == 1, "Импорт должен оставаться доступным в справочнике.");
            tabs.SelectedTab = tabs.TabPages.Cast<TabPage>().Single(page => page.Text.StartsWith("Чёрный список"));
            ListViewItem selected = blocked.SelectedItems[0];
            CertificateInventorySnapshot refreshed = new(DateTimeOffset.UtcNow.AddSeconds(10),
                [russian, possible, historical, foreign, machineBlocked],
                [UserRoot, MachineRoot, UserBlocked, MachineBlocked], [], 5);
            form.ShowSnapshot(refreshed);
            Require(ReferenceEquals(selected, blocked.SelectedItems[0]),
                "Неизменный опрос должен сохранять строки и выделение.");
            form.SetScanning(true, showProgress: false);
            Require(!import.Enabled && !add.Enabled && !remove.Enabled,
                "Во время чтения ручные изменения не должны запускаться и теряться.");
            form.SetScanning(false);
            form.SetOperationBusy(true);
            Require(!import.Enabled && !remove.Enabled && !Button(form, "Проверить сейчас").Enabled,
                "Во время операции импорт, изменение списка и проверка должны быть отключены.");
            form.SetOperationBusy(false);
            scope.SelectedIndex = 2;
            InventoryCertificate backupOnly = machineBlocked with
            {
                Locations = [],
                BackupScopes = [StoreLocation.LocalMachine]
            };
            form.ShowSnapshot(refreshed with { Certificates = [backupOnly], ObservationCount = 0 });
            Require(blocked.Items.Count == 1 && ReferenceEquals(blocked.Items[0].Tag, backupOnly),
                "Резервная копия компьютера должна остаться в чёрном списке после внешнего удаления Disallowed.");
            blocked.Items[0].Selected = true;
            remove.PerformClick();
            Require(ReferenceEquals(callback, backupOnly),
                "Кнопка снятия запрета должна открывать восстановление сохранённого сертификата.");
        }
        finally
        {
            form.Dispose();
        }
    }

    private static InventoryCertificate Certificate(string id, string name, bool russian, bool possible,
        bool historical, IReadOnlyList<CertificateStoreDescriptor> locations, byte[] der) =>
        new(new CertificateMetadata(id, name, $"CN={name}", "CN=Издатель", id,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(80), [], [], der),
            locations, new CertificateClassification(russian, possible, historical, [], []), []);

    private static ListView List(TabControl tabs, string prefix) => tabs.TabPages.Cast<TabPage>()
        .Single(page => page.Text.StartsWith(prefix)).Controls.OfType<ListView>().Single();

    private static Button Button(Control parent, string caption) => Controls(parent).OfType<Button>()
        .Single(button => button.Text == caption);

    private static IEnumerable<Control> Controls(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (Control descendant in Controls(child))
                yield return descendant;
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
