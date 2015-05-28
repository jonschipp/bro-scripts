##! Constants definitions for rip.

module Rip;

export {
        ## Types of RIP messages. See :rfc:`2453`.
        const message_types = {
                [1] = "RIP_REQUEST",
                [2] = "RIP_RESPONSE",
        } &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };
}
