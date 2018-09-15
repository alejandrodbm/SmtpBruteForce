USAGE:
go run main.go [target email] [smtp server] [smtp port: 465|587] [Keywords List] [Password length] [Number of procs] [Delay(ms)]

EXAMPLE OF USE:
go run main.go email@gmail.com smtp.gmail.com 465 words.txt 1 1 500

[target email]: The victim's email.
[smtp server]: Only can use this tool for smtp servers running under port 465/587.
[smtp port: 465|587]: Port under service is listening.
[Keywords List]: Text file fill with words separated by commas.
[Password length]: Length of the resulted word in the combination process. if "1" is used, the word list is used as a simple dictionary but
                   if the number is equal or greater than "2", the words contained in the text file will be used to build combinations growing
                   until you reach the length specified in password length.
[Number of procs]: Amount of concurrency processes needed.
[Delay(ms)]: Waiting between concurrent processes for the execution.
