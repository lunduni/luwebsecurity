"""Takes input:
1. k where k-1 is the degree of the polynomial
2. n, number of participants
3. the polynomial in a string format, e.g. "2*x^2 + 3*x + 4"
4. points at f(1), string format, e.g. "5, 10, 15"
5. Coordinates from k-1 participants, string format, (x,y), e.g. "(1,5), (2,10)"
"""


class MyPolynomial:
    coefficients = []
    valueAt1 = 0

    def __init__(self, polynomial):
        self.coefficients = polynomial.replace(" ", "").split("+")
        self.valueAt1 = self.evaluate(1)

    def evaluate(self, x):
        value = 0
        for term in self.coefficients:
            if "x^" in term:
                coeff, power = term.split("x^")
                coeff = int(coeff) if coeff else 1
                power = int(power)
                value += coeff * (x**power)
            elif "x" in term:
                coeff = term.replace("x", "")
                coeff = int(coeff) if coeff else 1
                value += coeff * x
            else:
                value += int(term)

        return value


class SecretPolynomial:
    k = 0
    n = 0
    coordinates = []

    def __init__(self, k, n, coordinates):
        self.k = k
        self.n = n
        self.coordinates = coordinates

    def lagrange_interpolation(self, x):
        total = 0
        for i in range(self.k):
            term = 1
            for j in range(self.k):
                if i != j:
                    term = (
                        (x - self.coordinates[j][0])
                        * term
                        / (self.coordinates[i][0] - self.coordinates[j][0])
                    )
            total += term * self.coordinates[i][1]
        return total


def main():
    k = int(input("Enter k (degree of polynomial + 1): ") or "3")
    n = int(input("Enter n (number of participants): ") or "5")
    polynomial_str = (
        input("Enter the polynomial (e.g. '2*x^2 + 3*x + 4'): ") or "16 +  4x + 14x^2"
    )
    points_str = (
        input("Enter the points at f(1) (e.g. '5, 10, 15'): ") or "45, 57, 30, 39"
    )
    coordinates_str = (
        input("Enter the coordinates from k-1 participants (e.g. '(1,5), (2,10)'): ")
        or "(2.471), (4.1381)"
    )

    polynomial = MyPolynomial(polynomial_str)
    print(f"Value at f(1): {polynomial.valueAt1}")

    other_shares = [int(p.strip()) for p in points_str.split(",") if p.strip()]
    f_at_1 = polynomial.valueAt1 + sum(other_shares)

    coordinates = []
    coordinates.append((1, f_at_1))
    for coord in coordinates_str.split(","):
        x, y = coord.strip().strip("()").split(".")
        coordinates.append((int(x), int(y)))

    secret_poly = SecretPolynomial(k, n, coordinates)
    secret_value = secret_poly.lagrange_interpolation(0)
    print(f"The secret value is: {secret_value}")


if __name__ == "__main__":
    main()
