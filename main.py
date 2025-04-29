from server import Server
from car import Car
from app import App

def main():
    # Setup
    server = Server()
    owner_app = App("Owner123", server)
    car = Car("CarABC", server)

    # Authentication
    if owner_app.authenticate_to_car(car):
        car.unlock()
        car.start()

if __name__ == "__main__":
    main()