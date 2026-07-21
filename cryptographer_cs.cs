// cryptographer_cs.cs — криптограф (шифрование файлов) на C# (.NET Core)

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class Cryptographer
{
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int Iterations = 100000;
    private const int KeySize = 32;

    static byte[] DeriveKey(string password, byte[] salt)
    {
        using var derive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        return derive.GetBytes(KeySize);
    }

    static async Task EncryptFile(string input, string output, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = DeriveKey(password, salt);

        using var aes = new AesGcm(key);
        byte[] plaintext = await File.ReadAllBytesAsync(input);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        using var fs = new FileStream(output, FileMode.Create);
        await fs.WriteAsync(salt, 0, salt.Length);
        await fs.WriteAsync(nonce, 0, nonce.Length);
        await fs.WriteAsync(ciphertext, 0, ciphertext.Length);
        await fs.WriteAsync(tag, 0, tag.Length);

        Console.WriteLine($"Файл зашифрован: {output}");
    }

    static async Task DecryptFile(string input, string output, string password)
    {
        byte[] salt = new byte[SaltSize];
        byte[] nonce = new byte[NonceSize];
        using var fs = new FileStream(input, FileMode.Open);
        await fs.ReadAsync(salt, 0, salt.Length);
        await fs.ReadAsync(nonce, 0, nonce.Length);

        long remaining = fs.Length - fs.Position;
        if (remaining < TagSize)
            throw new Exception("Некорректный зашифрованный файл");

        int cipherLen = (int)(remaining - TagSize);
        byte[] ciphertext = new byte[cipherLen];
        byte[] tag = new byte[TagSize];
        await fs.ReadAsync(ciphertext, 0, cipherLen);
        await fs.ReadAsync(tag, 0, tag.Length);

        byte[] key = DeriveKey(password, salt);
        using var aes = new AesGcm(key);
        byte[] plaintext = new byte[cipherLen];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        await File.WriteAllBytesAsync(output, plaintext);
        Console.WriteLine($"Файл расшифрован: {output}");
    }

    static async Task Main(string[] args)
    {
        if (args.Length != 4)
        {
            Console.WriteLine("Использование: dotnet run <encrypt|decrypt> <input> <output> <password>");
            return;
        }
        try
        {
            if (args[0] == "encrypt")
                await EncryptFile(args[1], args[2], args[3]);
            else if (args[0] == "decrypt")
                await DecryptFile(args[1], args[2], args[3]);
            else
                Console.WriteLine("Режим должен быть encrypt или decrypt");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка: {ex.Message}");
        }
    }
}
