#include <stdio.h>
#include <string.h>

#include "sha256.h"

int main(void) {
    char *M = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer mauris eros, commodo non blandit in, varius nec diam. In lobortis mauris sed eros rhoncus, et bibendum tortor fermentum. Mauris feugiat est vitae pulvinar ullamcorper. Donec convallis lectus nec sodales elementum. Suspendisse enim dolor, vehicula non tempor vel, rhoncus in ipsum. Phasellus porttitor justo non sem laoreet iaculis. Integer erat urna, mattis nec iaculis sit amet, pretium ut augue. Nunc a purus a eros pulvinar dapibus. Integer pellentesque augue et ante sagittis facilisis. Suspendisse lacinia, arcu at porttitor porttitor, purus lectus congue sapien, at iaculis tellus turpis et libero. Aenean lacinia vitae nibh et ullamcorper. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Phasellus sollicitudin molestie iaculis. Etiam tincidunt luctus arcu et cursus. Cras quis viverra arcu. Fusce nec dui et lorem sagittis hendrerit a in magna. In eget elementum neque, ac auctor purus. In bibendum elit ante, nec euismod elit vehicula quis. Cras lacus arcu, molestie at dapibus non, tempus quis leo. Maecenas in ante sit amet orci tincidunt euismod. Maecenas et massa congue, tristique libero vel, lacinia arcu. Suspendisse potenti. Suspendisse sagittis dapibus nisi, quis ultricies est ultrices vitae. Ut magna est, ultrices vitae lorem ut, sollicitudin ornare turpis. Vivamus luctus magna tellus, at consectetur metus commodo quis. Donec suscipit viverra lorem ut gravida. Donec sit amet pharetra magna. Cras sed diam enim. Aenean tempus, enim nec hendrerit feugiat, tellus leo convallis lacus, id aliquam neque velit quis augue. Curabitur semper euismod enim at imperdiet. Phasellus quis luctus neque. Cras nec ligula nulla. Aliquam urna leo, vulputate a lorem tempus, tristique tempus ex. Curabitur elementum felis felis, sit amet sollicitudin justo bibendum ut. Morbi at gravida nulla. Cras pulvinar pretium eros, sed feugiat eros porttitor vitae. Sed vel nibh magna. Fusce maximus nulla velit, a mollis dui hendrerit sit amet. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Mauris suscipit congue risus ac porttitor. Suspendisse a auctor felis, euismod rhoncus nunc. Duis malesuada urna quis lacus rutrum, in ultricies ligula malesuada. Maecenas consectetur sed lectus sed aliquam. Donec viverra, ligula vitae condimentum euismod, metus tortor lacinia risus, id blandit diam enim id diam. Proin mattis lectus enim, in convallis arcu ultrices placerat. Maecenas quis imperdiet neque. Quisque vel ipsum risus. Quisque nisi augue, pharetra sed efficitur eget, finibus vitae risus. Donec sit amet facilisis metus. Suspendisse et quam vitae elit accumsan condimentum vitae et nibh. Mauris luctus pulvinar nibh, quis fringilla diam lobortis ac. Sed eu condimentum felis. Aliquam at libero at augue molestie auctor et eget libero. Nunc quis sollicitudin nisi. Ut lacinia nisl finibus, dapibus nisi tempor, maximus lorem.";
   
    uint8_t hash[32] = { 0 };

    calculate(M, strlen(M), hash);

    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }

    uint8_t expected[32] = {
        0xf4, 0x0d, 0x09, 0x85, 0xd8, 0xcc, 0xa2, 0x3d, 
        0x0d, 0x26, 0x95, 0x59, 0x40, 0x5e, 0x12, 0x9a, 
        0x9f, 0xf1, 0x63, 0x4b, 0xfb, 0xf7, 0x68, 0x36, 
        0xbc, 0xa5, 0xd5, 0x7f, 0x2d, 0xee, 0xd8, 0xda
    };

    printf(": %s\n", memcmp(hash, expected, 32) == 0 ? "the same" : "not the same");

    return 0;
}
