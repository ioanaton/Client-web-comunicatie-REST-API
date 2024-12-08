
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>      
#include <unistd.h>      
#include <sys/socket.h> 
#include <string.h>
#include <netinet/in.h> 
#include <stdio.h>
#include <stdlib.h>  
#include <ctype.h>
#include "buffer.h"
#include "helpers.h"
#include "requests.h"
#define REGISTER "/api/v1/tema/auth/register"
#define LOGIN "/api/v1/tema/auth/login"
#define LOGOUT "/api/v1/tema/auth/logout"
#define ENTER_LIBRARY "/api/v1/tema/library/access"
#define ADD_BOOK "/api/v1/tema/library/books"
#define GET_BOOK "/api/v1/tema/library/books/"
#define JSON "application/json"
#define PORT 8080
#define HOST "54.170.241.232"

#define MAX_LENGTH 1000

typedef struct {
    int sockfd;
    char command[MAX_LENGTH];
    char *url_address;
    char *token;
    char *session;
} Connection;

typedef struct 
{
    char password[MAX_LENGTH];
    char username[MAX_LENGTH];
} Data;

typedef struct
{
    char title[200], author[200], genre[200], page_count[200], publisher[200];
} Book;

typedef struct
{
    char *message;
    char *line;
    char *body_data_buffer;
} Buf_data;

void freeConnection(Connection *connection , Data *data) {
    free(connection->url_address);
    free(connection->token);
    free(connection->session);
    free(connection);
    free(data);
}

void register_user(Connection *connection, Data *data) {

    printf("username=");
    scanf("%[^\n]%*c", data->username);
    printf("password=");
    scanf("%[^\n]%*c", data->password);
    char *username_helper = strtok(data->username, "\n");
    char *password_helper = strtok(data->password, "\n");

    if(strlen(data->username)==0){
        printf("error, empty username");
        return;
    }
    char *helper = calloc(4096, sizeof(char));
    memset(helper, 0, 4096);
    sprintf(helper, "{\n\t\"username\":\"%s\",\n\t\"password\":\"%s\"\n}", username_helper, password_helper);
    char *server_response;
    
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    char *request = compute_post_request(HOST, REGISTER, JSON, &helper, 1, NULL, 0);
    send_to_server(connection->sockfd, request);
    server_response = receive_from_server(connection->sockfd);

    char *c = strtok(server_response, "\n\r");
    if (c[9] == '2'){
        printf("Registered with succes!\n");   
    } else {
        printf("Erorr! Username already taken.\n");
    }
}

void login(Connection *connection, Data *data){
    printf("username=");
    scanf("%[^\n]%*c", data->username);
    printf("password=");
    scanf("%[^\n]%*c", data->password);

    if(strlen(data->username)==0){
        printf("Error! Invalid username.");
        return;
    }
    char *request;
    char *helper = calloc(4096, sizeof(char));
    char *username_helper = strtok(data->username, "\n");
    char *password_helper = strtok(data->password, "\n");
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

    memset(helper, 0, 4096);
    sprintf(helper, "{\n\t\"username\":\"%s\",\n\t\"password\":\"%s\"\n}", username_helper,password_helper);
    request  = compute_post_request(HOST, LOGIN, JSON, &helper, 1, NULL, 0);
    send_to_server(connection->sockfd, request);
    
    char *server_response;
    server_response = receive_from_server(connection->sockfd);
    char *copy = strdup(server_response);
    char *review = strstr(server_response, "Cookie");
    copy = strtok(copy, "\n");
    if(copy[9] != '2') {
        printf("Erorr!Wrong username or password. Please try again!\n");
    }
    review = strtok(review, ";");
    printf("Success! You are logged in!\n");
    memset(connection->session, 0, 4096);
    strcpy(connection->session, review + 8);
};

void logout(Connection *connection, Data *data){
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    char *request = compute_get_request(HOST, LOGOUT, NULL, &connection->session, 1);
    send_to_server(connection->sockfd, request);
    char *server_response;
    server_response = receive_from_server(connection->sockfd);
    switch(server_response[9]) {
        case '2':
            memset(connection->session, 0, 4096);
            memset(connection->token, 0, 4096);
            printf("Success!You logged out!\n");
            break;
        case '4': 
            printf("Error. You are not logged in!\n");
            break;
        default:
            printf("An error has occured. Please, try again!\n");
            break;
    }   
} ;

void enter_library(Connection *connection, Data *data) {
    if(strlen(connection->session) == 0) {
        printf("Error!You are not logged in!\n");
        return;
    }
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    char *request = compute_get_request(HOST, ENTER_LIBRARY, NULL, &connection->session, 1);
    send_to_server(connection->sockfd, request);
    char *server_response;
    server_response = receive_from_server(connection->sockfd);
    char *r = strstr(server_response, "token");
    if (r == NULL) {
        printf("An error has occured!\n");
        return;
    }
    memset(connection->token, 0, 4096);
    r = r + 8;
    strcpy(connection->token, strtok(r,"\"" ));
    switch(strlen(connection->token)) {
        case 0:
            printf("An error has occured\n");
            break;
        default:
            printf("Success!You entered the library!\n");
            break;
    }
};

void add_book(Connection *connection, Data *data){
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    if (strlen(connection->token) == 0) {
        printf("Error! You don't have access to the library\n");
        return;
    }
    int verify = 0;
    Book *book = malloc(sizeof(Book));
    printf("title=");
    scanf("%[^\n]%*c", book->title);
    printf("author=");
    scanf("%[^\n]%*c", book->author);
    printf("genre=");
    scanf("%[^\n]%*c", book->genre);
    printf("publisher=");
    scanf("%[^\n]%*c", book->publisher);
    int i;
    printf("page_count=");
    scanf("%[^\n]%*c", book->page_count);

    if (strlen(book->title) == 0 || strlen(book->author)==0 || strlen(book->publisher)==0 || strlen(book->genre)==0  )
        return;
    char *page_count_helper = strtok(book->page_count, "\n");
    char *publisher_helper = strtok(book->publisher, "\n");
    char *genre_helper = strtok(book->genre, "\n");
    char *author_helper = strtok(book->author, "\n");
    char *title_helper = strtok(book->title, "\n");
    char *helper = calloc(4096, sizeof(char));
    memset(helper, 0, BUFLEN);
    if(strlen(book->author) < 1){
        verify = 1;
        printf("Error!Invalid book");
    }
    for(i = 0; i < strlen(page_count_helper);i++) {
        if (page_count_helper[i] < '0' || page_count_helper[i] > '9') {
            verify = 1;
            printf("Error! Invalid page count!\n");
            break;
        }
    }
    if (verify) {
        return;
    }
    snprintf(helper, BUFLEN, "{\n\t\"title\":\"%s\",\n\t\"author\":\"%s\",\n\t\"genre\":\"%s\",\n\t\"page_count\":\"%s\",\n\t\"publisher\":\"%s\"\n}",
    title_helper, author_helper, genre_helper, page_count_helper, publisher_helper);
            
    Buf_data *buff=malloc(sizeof(Buf_data)); 
    buff->message = calloc(BUFLEN, sizeof(char));
    buff->line = calloc(LINELEN, sizeof(char));
    buff->body_data_buffer = calloc(LINELEN, sizeof(char));
    sprintf(buff->line, "POST %s HTTP/1.1", ADD_BOOK);
    // secventa de cod preluata din cadrul laboratorului
    compute_message(buff->message, buff->line);
    sprintf(buff->line, "Host: %s", HOST);
    compute_message(buff->message, buff->line);
    if(connection->token != NULL) {
        memset(buff->line, 0, LINELEN);
        strcpy(buff->line, "Authorization: Bearer ");
        strcat(buff->line, connection->token);
        compute_message(buff->message, buff->line);
        memset(buff->line, 0, LINELEN);
    }
    memset(buff->body_data_buffer, 0, LINELEN);
    for (int i = 0; i < 1; ++i) {
        strcat(buff->body_data_buffer, &helper[i]);
        if (i != 0) {
            strcat(buff->body_data_buffer, "&");
        }
    }
    sprintf(buff->line, "Content-Type: %s", JSON);
    compute_message(buff->message, buff->line);
  
    sprintf(buff->line, "Content-Length: %lu", strlen(buff->body_data_buffer));
    compute_message(buff->message, buff->line);
    compute_message(buff->message, "");
    memset(buff->line, 0, LINELEN);
    strcat(buff->message, buff->body_data_buffer);

    free(buff->line);
    free(buff->body_data_buffer);
    send_to_server(connection->sockfd, buff->message);
    printf("The book was succesfully added!\n");
} ;

void get_books(Connection *connection, Data *data){
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    if(!strlen(connection->token)) {
        printf("Error! You do not have access to the books.\n");
        return;
    }
    Buf_data *buff=malloc(sizeof(Buf_data)); 
    buff->message = calloc(BUFLEN, sizeof(char));
    buff->line = calloc(LINELEN, sizeof(char));
    sprintf(buff->line, "GET %s HTTP/1.1", ADD_BOOK);
    compute_message(buff->message, buff->line);
    sprintf(buff->line, "Host: %s", HOST);
    compute_message(buff->message, buff->line);
    if(connection->token != NULL) {
        memset(buff->line, 0, LINELEN);
        strcpy(buff->line, "Authorization: Bearer ");
        strcat(buff->line, connection->token);
        compute_message(buff->message, buff->line);
    }
    compute_message(buff->message, "");
    free(buff->line);
    send_to_server(connection->sockfd, buff->message);
    char *server_response;
    server_response = receive_from_server(connection->sockfd);
    char *content = strstr(server_response, "[");
    if(content == NULL) {
        printf("An error has occured!\n");
        return;
    }
        printf("%s\n", content);
} ;

void get_book(Connection *connection, Data *data) {
    if (strlen(connection->token) == 0) {
        printf("Error!You don't have access to the books.\n");
        return;
    }
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    printf("id=");
    char id[1000]; 
    fgets(id, 1000, stdin);
    memset(connection->url_address, 0, 1000);
    strcpy(connection->url_address, GET_BOOK);
    strcat(connection->url_address, id);
    connection->url_address = strtok(connection->url_address, "\n");

    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    sprintf(line, "GET %s HTTP/1.1", connection->url_address);
    compute_message(message, line);
    sprintf(line, "Host: %s", HOST);
    compute_message(message, line);

    if(connection->token != NULL) {
        memset(line, 0, LINELEN);
        strcpy(line, "Authorization: Bearer ");
        strcat(line, connection->token);
        compute_message(message, line);
    }
    compute_message(message, "");
    free(line);
    send_to_server(connection->sockfd, message);
    char *response;
    response = receive_from_server(connection->sockfd);
    char *show = strrchr(response, '{');
    show = strtok(show, "]");
    if(show == NULL) {
        printf("An error has occured. The ID is not correct.\n");
    } else {
        printf("%s\n", show);
    }
            
};

void delete_book(Connection *connection, Data *data) {
    if (strlen(connection->token) == 0) {
        printf("Error! You don't have access\n");
        return;
    }
    connection->sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
    printf("id=");
    char id[1000]; 
    fgets(id, 1000, stdin);
    memset(connection->url_address, 0, 1000);
    strcpy(connection->url_address, GET_BOOK);
    strcat(connection->url_address, id);
    connection->url_address = strtok(connection->url_address, "\n");
    Buf_data *buff=malloc(sizeof(Buf_data)); 
    buff->message = calloc(BUFLEN, sizeof(char));
    buff->line = calloc(LINELEN, sizeof(char));
    sprintf(buff->line, "GET %s HTTP/1.1", connection->url_address);
    compute_message(buff->message, buff->line);
    sprintf(buff->line, "Host: %s", HOST);
    compute_message(buff->message, buff->line);

    if(connection->token != NULL) {
        memset(buff->line, 0, LINELEN);
        strcpy(buff->line, "Authorization: Bearer ");
        strcat(buff->line, connection->token);
        compute_message(buff->message, buff->line);
    }
    char *str = calloc(4096, sizeof(char));
    compute_message(buff->message, "");
    char *server_respunse;
    free(buff->line);
    buff->message = buff->message + 3;
    strcpy(str, "DELETE");
    strcat(str, buff->message);
    send_to_server(connection->sockfd, str);
    server_respunse = receive_from_server(connection->sockfd);
    switch(server_respunse[9]) {
        case '4':
            printf("Error! Invalid ID.\n");
            break;
        case '2':
            printf("The book was succesfully deleted.\n");
            break;
        default:
            printf("An error has occured.\n");
    }
};

int main() {
    Connection *connection = malloc(sizeof(Connection));
    if(connection == NULL) {
        fprintf(stderr, "Error! Memory alloc failed!");
    } 
    connection->url_address = calloc(LINELEN, sizeof(char));
    connection->token = calloc(4096, sizeof(char));
    connection->session = calloc(4096, sizeof(char));
    Data *data = malloc(sizeof(Data));

    while(1) {
        fgets(connection->command, MAX_LENGTH, stdin);
        connection->command[strcspn(connection->command, "\n")] = '\0';
        
        if (strcmp(connection->command, "exit") == 0) {
            break;
        } else if(strcmp(connection->command, "register") == 0) {
            register_user(connection, data);
        } else if(strcmp(connection->command, "login") == 0) {
            login(connection, data);
        } else if(strcmp(connection->command, "logout") == 0) {
            logout(connection, data);
        } else if(strcmp(connection->command, "enter_library") == 0) {
            enter_library(connection, data);
        } else if(strcmp(connection->command, "add_book") == 0) {
            add_book(connection, data);
        } else if(strcmp(connection->command, "get_books") == 0) {
            get_books(connection, data);
        } else if(strcmp(connection->command, "get_book") == 0) {
            get_book(connection, data);
        } else if(strcmp(connection->command, "delete_book") == 0) {
            delete_book(connection, data);
        } else {
            printf("Error! Unknown command.");
        }

    }
    freeConnection(connection, data);

}
