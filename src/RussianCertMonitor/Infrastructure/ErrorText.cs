using System.ComponentModel;
using System.Security.Cryptography;

namespace RussianCertMonitor.Infrastructure;

internal static class ErrorText
{
    public static string Describe(Exception error) => error switch
    {
        UnauthorizedAccessException => "Доступ запрещён. Проверьте права к указанному файлу или хранилищу.",
        Win32Exception { NativeErrorCode: 5 } => "Windows запретила доступ. Проверьте права для выбранной операции.",
        Win32Exception { NativeErrorCode: 1223 } => "Запрос прав администратора отменён. Операция не выполнена.",
        FileNotFoundException => "Файл не найден. Проверьте, что он существует и не был перемещён.",
        DirectoryNotFoundException => "Папка не найдена. Выберите существующую папку.",
        IOException when (error.HResult & 0xffff) is 32 or 33 => "Файл занят другой программой. Закройте её и повторите операцию.",
        TimeoutException => "Windows не ответила вовремя. Результат операции не подтверждён; обновите состояние перед повтором.",
        CryptographicException => "Windows не смогла прочитать сертификат. Требуется один корректный публичный сертификат CER/CRT. " + error.Message,
        _ => error.Message
    };
}
