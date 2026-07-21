🔐 CryptoFile — криптограф (шифрование файлов)
Мощный инструмент для шифрования и дешифрования файлов с использованием AES-256-GCM.
Поддерживает большие файлы, прогресс-бар, аутентификацию, хэширование пароля через PBKDF2.
Реализован на 7 языках программирования для демонстрации криптографических алгоритмов и работы с файлами.

https://img.shields.io/github/repo-size/yourname/cryptofile
https://img.shields.io/github/stars/yourname/cryptofile?style=social
https://img.shields.io/badge/License-MIT-blue.svg

🧠 Концепция
CryptoFile — это утилита для безопасного шифрования и дешифрования файлов. Она позволяет:

✅ Шифровать любой файл с использованием пароля.

✅ Дешифровать файл обратно с тем же паролем.

✅ Аутентификация — используется AES-256-GCM, гарантирующий целостность данных.

✅ Соль и nonce генерируются случайно и сохраняются вместе с зашифрованными данными.

✅ Поддержка больших файлов — потоковое шифрование без загрузки всего файла в память.

✅ Прогресс-бар для наглядности при работе с большими файлами.

✅ Кроссплатформенность — работает на Windows, Linux, macOS.

✅ Простой интерфейс — всё через командную строку.

🚀 Как запустить
Каждая версия использует соответствующие криптографические библиотеки. Инструкции по установке зависимостей и запуску приведены ниже.

Python
bash
pip install cryptography
python cryptographer_python.py encrypt input.txt output.enc mypassword
python cryptographer_python.py decrypt output.enc decrypted.txt mypassword
C++
bash
# Требуется OpenSSL (sudo apt install libssl-dev)
g++ -std=c++17 cryptographer_cpp.cpp -o cryptographer -lssl -lcrypto
./cryptographer encrypt input.txt output.enc mypassword
./cryptographer decrypt output.enc decrypted.txt mypassword
Java
bash
# Компиляция (Java 8+)
javac cryptographer_java.java
java cryptographer_java encrypt input.txt output.enc mypassword
java cryptographer_java decrypt output.enc decrypted.txt mypassword
C# (.NET Core)
bash
dotnet add package System.Security.Cryptography
dotnet run -- encrypt input.txt output.enc mypassword
dotnet run -- decrypt output.enc decrypted.txt mypassword
Go
bash
go mod init cryptographer
go get golang.org/x/crypto/pbkdf2
go run cryptographer_go.go encrypt input.txt output.enc mypassword
go run cryptographer_go.go decrypt output.enc decrypted.txt mypassword
Rust
bash
cargo init
cargo add aes-gcm rand pbkdf2 sha2
cargo run -- encrypt input.txt output.enc mypassword
cargo run -- decrypt output.enc decrypted.txt mypassword
JavaScript (Node.js)
bash
npm install crypto
node cryptographer_js.js encrypt input.txt output.enc mypassword
node cryptographer_js.js decrypt output.enc decrypted.txt mypassword
🧩 Пример использования
bash
$ ./cryptographer encrypt photo.jpg photo.enc "superSecret123"
Шифрование... [####################] 100% (2.4 МБ)
Файл зашифрован: photo.enc

$ ./cryptographer decrypt photo.enc decrypted_photo.jpg "superSecret123"
Дешифрование... [####################] 100% (2.4 МБ)
Файл расшифрован: decrypted_photo.jpg
📦 Содержимое репозитория
Файл	Язык	Особенности
cryptographer_python.py	Python	cryptography, прогресс-бар, GCM
cryptographer_cpp.cpp	C++	OpenSSL EVP, прогресс-бар, GCM
cryptographer_java.java	Java	javax.crypto, AES/GCM/NoPadding, PBKDF2
cryptographer_cs.cs	C#	System.Security.Cryptography, AES-GCM (требуется .NET Core 3.0+)
cryptographer_go.go	Go	crypto/aes, crypto/cipher, pbkdf2
cryptographer_rs.rs	Rust	aes-gcm, pbkdf2, rand, progress bar
cryptographer_js.js	JavaScript	crypto модуль, async/await, прогресс
🔮 Расширенные функции
Поддержка потокового шифрования — экономия памяти.

Проверка целостности — при дешифровании проверяется тег аутентификации.

Настраиваемые параметры — количество итераций PBKDF2, размер соли.

📜 Лицензия
MIT — свободно используйте, модифицируйте и распространяйте.

🤝 Вклад
Приветствуются пул-реквесты с улучшениями, поддержкой новых алгоритмов и платформ.

⭐ Если проект помогает вам защищать данные — поставьте звёздочку!
