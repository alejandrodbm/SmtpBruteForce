USAGE:
go run main.go [target email] [smtp server] [smtp port: 465|587] [Keywords List] [Password length] [Number of procs] [Delay(ms)] [Round Robin(secs)]

EXAMPLE OF USE:
go run main.go email@gmail.com smtp.gmail.com 465 words.txt 1 1 500

PARAMETERS DESCRIPTION:
[target email]:       The victim's email.
[smtp server]:        Host of the smtp server.
[smtp port: 465|587]: To specify port under service is listening (465/587 ports only).
[Keywords List]:      Text file fill with words separated by commas.
[Password length]:    Length of the resulted word in the combination process. if "1" is used, the words list is used as a simple 
                      dictionary but if the number is equal or greater than "2", the words contained in the text file will be used to 
                      build combinations growing until the length specified is reached.
[Number of procs]:    Amount of concurrent processes needed.
[Delay(ms)]:          Wait between concurrent processes before resuming re-execution.
[Round Robin(secs)]:  To specify between the battery of attacks and the waits expressed in seconds.
                      * When this is enabled concurrency and delay is automatically disabled.
                      * Set "0" to disable the round robin.
