from .workflows import run_ping, run_dns, run_route
from .sequences.target_recon import run_target_recon
from .presentation.console import (
    show_dns_result,
    prompt_input,
    show_request,
    show_ping_result,
    pause,
    clear_screen,
    show_main_menu,
    show_header,
    show_error,
    prompt,
    show_networking_menu,
    show_route_result,
    show_route_mode_menu,
    show_recon_result,
)


def run_main_menu():
    while True:
        clear_screen()
        show_header()
        show_main_menu()
        selection = prompt("CATEGORY")

        if selection == "1":
            run_networking_menu()
        elif selection == "0":
            break
        else:
            show_error("Invalid selection you dingus!")

def run_networking_menu():
    while True:
        clear_screen()
        show_header()
        show_networking_menu()

        selection = prompt("TOOL")

        if selection == "1":
            clear_screen()
            show_header()

            target = ""
            go_back = False

            while not target:
                target = prompt_input("TARGET")

                if target == "0":
                    go_back = True
                    break

                if not target:
                    show_error("Target cannot be empty. Type 0 to go back.")

            if go_back:
                continue

            clear_screen()
            show_header()

            request, ping_result = run_ping(target)

            clear_screen()
            show_header()
            show_request(request)
            show_ping_result(ping_result)
            pause()

        elif selection == "2":
            clear_screen()
            show_header()

            query = ""
            go_back = False

            while not query:
                query = prompt_input("QUERY")

                if query == "0":
                    go_back = True
                    break

                if not query:
                    show_error("Query can not be empty. Type 0 to go back.")

            if go_back:
                continue

            record_type = prompt_input("RECORD TYPE", "A")
            if not record_type:
                record_type = "A"

            record_type = record_type.upper()

            clear_screen()
            show_header()

            request, dns_result = run_dns(query, record_type)

            clear_screen()
            show_header()
            show_request(request)
            show_dns_result(dns_result)
            pause()

        elif selection == "3":
            while True:
                clear_screen()
                show_header()

                target = ""
                show_route_mode_menu()

                go_back = False

                while True:
                    mode_selection = prompt_input("MODE", "1")

                    if not mode_selection:
                        mode_selection = "1"

                    if mode_selection == "0":
                        go_back = True
                        break

                    elif mode_selection == "1":
                        verbose = False
                        break

                    elif mode_selection == "2":
                        verbose = True
                        break
                    else:
                        clear_screen()
                        show_header()
                        show_route_mode_menu()
                        show_error("Invalid Selection.")

                if go_back:
                    break

                selected_mode = "verbose" if verbose else "compact"

                clear_screen()
                show_header()
                show_route_mode_menu(selected=selected_mode)

                while not target:
                    target = prompt_input("TARGET")

                    if target == "0":
                        go_back = True
                        break

                    if not target:
                        show_error("Target can not be empty.")

                if go_back:
                    continue

                clear_screen()
                show_header()

                request, route_result = run_route(target)

                clear_screen()
                show_header()
                show_request(request)
                show_route_result(route_result, verbose=verbose)
                pause()
                break

        elif selection == "4":
            clear_screen()
            show_header()

            target = ""
            go_back = False

            while not target:
                target = prompt_input("TARGET")

                if target == "0":
                    go_back = True
                    break

                if not target:
                    show_error("Target cannot be empty. Type 0 to go back.")

            if go_back:
                continue

            clear_screen()
            show_header()

            recon_result = run_target_recon(target)

            clear_screen()
            show_header()
            show_recon_result(recon_result)
            pause()

        elif selection == "0":
            break
        else:
            show_error("Invalid selection you dingus!")
