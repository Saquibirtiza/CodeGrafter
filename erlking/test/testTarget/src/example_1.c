#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <testbed.h>

#define FALSE 0
#define TRUE 1

#define SERVER_HELLO "Enter Information:\n"
#define R_FAILED "ACCESS_DENIED\n"

#define BUFFER_SIZE 64

int server_fd, new_client;
struct sockaddr_in address;
char pswd[21];
char FLAG[21];

int authenticatedFunction(char *input_str)
{
    FILE *file_p;
    file_p = fopen("/tmp/Log.txt", "a");
    fputs(input_str, file_p);
    fclose(file_p);
    return TRUE;
}
int setupServer()
{
    int opt = 1; // reuse address
    char* port_env = getenv("PORT");
    int port = 8081; // the port to use if no value is found
    if (port_env != NULL)
    {
        port = atoi(port_env);
    }

    // create socket file descriptor, attach to 8081
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
        return FALSE;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)))
        return FALSE;

    printf("Listening on port %i...\n", port);
    return TRUE;
}
int runServer()
{
    // Create a structure to store the request
    struct request
    {
        char buffer[BUFFER_SIZE];
        int authenticated;
    } req;

    int addrlen = sizeof(address);

    while (TRUE)
    {
        //Reset request structure contents
        memset(req.buffer, 0, sizeof(req.buffer));
        req.authenticated = FALSE;

        listen(server_fd, 10);
        new_client = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        send(new_client, SERVER_HELLO, strlen(SERVER_HELLO), 0);

        // Read and process input
        // ** Suggested patch change to recv(new_client, req.buffer, BUFFER_SIZE, 0)
        recv(new_client, req.buffer, 1024, 0);
        printf("Processing Input %s\n", req.buffer);

        // Authenticate request
        if (!strncmp(req.buffer, pswd, strlen(pswd)))
            req.authenticated = TRUE;

        // Request Authenticated
        if (req.authenticated != FALSE)
        {
            if (strlen(req.buffer) > strlen(pswd) + 2)
            {
                authenticatedFunction(req.buffer + strlen(pswd));
            }
            send(new_client, FLAG, strlen(FLAG), 0);
        }

        // Request Not Authenticated
        else
        {
            send(new_client, R_FAILED, strlen(R_FAILED), 0);
        }
        close(new_client);
        printf("Response Sent\n");
    }
    return TRUE;
}
int main(int argc, char **argv)
{
    // Assert that we are running on the testbed
    #ifndef NO_TESTBED
    assert_execution_on_testbed();
    #endif

    if (argc != 3)
    {
        printf("Usage: ./example_1.bin <server passcode (1-20 characters)> <flag (1-20 characters)>\n");
        printf("%d",argc);
        return -1;
    }
    if (strlen(argv[1]) > 20 || strlen(argv[2]) > 20)
    {
        printf("Usage: ./example_1.bin <server passcode (1-20 characters)> <flag (1-20 characters)>\n");
        return -1;
    }

    strcpy(pswd, argv[1]);
    strcpy(FLAG, argv[2]);
    strcpy(FLAG + strlen(FLAG), "\n");

    if (setupServer() != 1)
    {
        printf("Server not started\n");
        return -1;
    }
    runServer();
    return 0;
}
