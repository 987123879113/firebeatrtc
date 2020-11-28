import argparse
import datetime
import random
import sys

import rtcpass


def seed_checker(minval, maxval):
    def seed_range_checker(arg):
        try:
            f = int(arg)

        except ValueError:
            raise argparse.ArgumentTypeError("must be an integer")

        if f < minval or f > maxval:
            raise argparse.ArgumentTypeError("must be in range [" + str(minval) + " .. " + str(maxval)+"]")

        return f

    return seed_range_checker


def date_checker(val):
    try:
        f = int(val)

    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if not rtcpass.verify_date(f):
        raise argparse.ArgumentTypeError("not a valid date")

    return f

def get_current_date():
    now = datetime.datetime.now()
    date = "%02d%02d%02d" % ((now.year % 100), now.month, now.day)
    return int(date)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--verify', help='Verify password', default=None)
    group.add_argument('--serial', help='Serial/license number')

    parser.add_argument('--keycode', help='Key code', required='--serial' in sys.argv)
    parser.add_argument('--date', help='Date (optional, YYMMDD format)', type=date_checker, default=get_current_date())
    parser.add_argument('--seed', help='Seed (optional, 0-1023)', type=seed_checker(0, 1023), default=random.randrange(0, 1024))

    parser.add_argument('--retries', help='Retry count', default=10, type=int)

    args = parser.parse_args()

    if args.verify is not None:
        password = args.verify
        decoded_password = rtcpass.decode_firebeat_recovery_password(password)

        print("Input password: %s" % (password))

    else:
        for i in range(0, args.retries):
            password = rtcpass.encode_firebeat_recovery_password(args.serial, args.keycode, args.date, args.seed)
            decoded_password = rtcpass.decode_firebeat_recovery_password(password)

            if decoded_password['is_valid']:
                break

        print("Input serial: %s" % (args.serial))
        print("Input key code: %s" % (args.keycode))

    print()

    if args.verify or decoded_password['is_valid']:
        print("PASSWORD: %s" % password)
        print()

        print("Password Information:")
        print("\tSerial: %s" % decoded_password['serial'])
        print("\tKey code: %s" % decoded_password['keycode'])
        print("\tDate: %s" % decoded_password['date'])
        print("\tStatus: %s" % ("VALID" if decoded_password['is_valid'] else "INVALID"))

    else:
        print("Could not find a valid password")