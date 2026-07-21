// cryptographer_cpp.cpp — криптограф (шифрование файлов) на C++ (OpenSSL)

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <iomanip>
#include <chrono>

// Простая функция для отображения прогресса
void print_progress(size_t current, size_t total) {
    const int bar_width = 50;
    float progress = (float)current / total;
    int pos = bar_width * progress;
    std::cout << "\r[";
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << int(progress * 100.0) << "%";
    std::cout.flush();
}

// PBKDF2 для получения ключа из пароля
std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt, int iterations = 100000) {
    std::vector<unsigned char> key(32);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                      salt.data(), salt.size(),
                      iterations, EVP_sha256(),
                      key.size(), key.data());
    return key;
}

bool encrypt_file(const std::string& input, const std::string& output, const std::string& password) {
    // Читаем входной файл
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        std::cerr << "Не удалось открыть входной файл" << std::endl;
        return false;
    }
    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Генерируем соль и nonce
    std::vector<unsigned char> salt(16), nonce(12);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        std::cerr << "Ошибка генерации соли" << std::endl;
        return false;
    }
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
        std::cerr << "Ошибка генерации nonce" << std::endl;
        return false;
    }

    // Выводим ключ из пароля
    auto key = derive_key(password, salt);

    // Шифрование с использованием AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста" << std::endl;
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), nonce.data())) {
        std::cerr << "Ошибка инициализации шифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Шифруем данные
    std::vector<unsigned char> ciphertext(plaintext.size() + 16); // дополнительное место для тега
    int outlen = 0, tmplen = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size())) {
        std::cerr << "Ошибка шифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &tmplen)) {
        std::cerr << "Ошибка завершения шифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outlen += tmplen;
    std::vector<unsigned char> tag(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
        std::cerr << "Ошибка получения тега" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    // Записываем выходной файл: соль + nonce + ciphertext + tag
    std::ofstream out(output, std::ios::binary);
    if (!out) {
        std::cerr << "Не удалось создать выходной файл" << std::endl;
        return false;
    }
    out.write((char*)salt.data(), salt.size());
    out.write((char*)nonce.data(), nonce.size());
    out.write((char*)ciphertext.data(), outlen);
    out.write((char*)tag.data(), tag.size());
    out.close();

    std::cout << "Файл зашифрован: " << output << std::endl;
    return true;
}

bool decrypt_file(const std::string& input, const std::string& output, const std::string& password) {
    // Читаем зашифрованный файл
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        std::cerr << "Не удалось открыть входной файл" << std::endl;
        return false;
    }
    std::vector<unsigned char> salt(16), nonce(12);
    in.read((char*)salt.data(), salt.size());
    in.read((char*)nonce.data(), nonce.size());
    // Читаем остаток (ciphertext + tag)
    std::vector<unsigned char> ciphertext_tag((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (ciphertext_tag.size() < 16) {
        std::cerr << "Некорректный зашифрованный файл" << std::endl;
        return false;
    }
    size_t ct_len = ciphertext_tag.size() - 16;
    std::vector<unsigned char> tag(ciphertext_tag.begin() + ct_len, ciphertext_tag.end());
    ciphertext_tag.resize(ct_len);

    auto key = derive_key(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста" << std::endl;
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), nonce.data())) {
        std::cerr << "Ошибка инициализации дешифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Устанавливаем ожидаемый тег
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data())) {
        std::cerr << "Ошибка установки тега" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> plaintext(ciphertext_tag.size() + 16);
    int outlen = 0, tmplen = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext_tag.data(), ciphertext_tag.size())) {
        std::cerr << "Ошибка дешифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) {
        std::cerr << "Ошибка дешифрования (неверный пароль или повреждённые данные)" << std::endl;
        return false;
    }
    outlen += tmplen;
    plaintext.resize(outlen);

    std::ofstream out(output, std::ios::binary);
    if (!out) {
        std::cerr << "Не удалось создать выходной файл" << std::endl;
        return false;
    }
    out.write((char*)plaintext.data(), plaintext.size());
    out.close();
    std::cout << "Файл расшифрован: " << output << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Использование: " << argv[0] << " <encrypt|decrypt> <input> <output> <password>" << std::endl;
        return 1;
    }
    std::string mode = argv[1];
    std::string input = argv[2];
    std::string output = argv[3];
    std::string password = argv[4];

    if (mode == "encrypt") {
        if (!encrypt_file(input, output, password)) return 1;
    } else if (mode == "decrypt") {
        if (!decrypt_file(input, output, password)) return 1;
    } else {
        std::cerr << "Режим должен быть encrypt или decrypt" << std::endl;
        return 1;
    }
    return 0;
}
