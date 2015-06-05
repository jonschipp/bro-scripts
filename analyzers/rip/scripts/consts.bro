##! Constants definitions for rip.

module Rip;

export {
        ## Types of RIP messages. See :rfc:`2453`.
        const command_types = {
                [1] = "request",
                [2] = "response",
        } &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };

        const update_types = {
                [1] = "unsolicited",
                [2] = "solicited",
        } &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };
}
