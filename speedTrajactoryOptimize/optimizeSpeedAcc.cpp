#include <cppad/ipopt/solve.hpp>
#include <iostream>
#include <cassert>

// Constants and derived quantities
double lambda1 = 1000, lambda2 = 1, lambda3 = 1;
double D = 186.32;
double v_0 = 12.79, t_g = 11.38;

class FG_eval {
public:
    using ADvector = CppAD::vector<CppAD::AD<double>>;

    void operator()(ADvector& fg, const ADvector& x) {
        assert(fg.size() == 3);  // Updated based on new constraint counts
        assert(x.size() == 2);

        // Extract variables from the input vector x
        CppAD::AD<double> a = x[0];
        CppAD::AD<double> v = x[1];


        CppAD::AD<double> d = (v * v - v_0 * v_0) / (2.0 * a) + v * (t_g - (v - v_0) / a);

        // VT-micro
        double M[4][4] = {
            {-7.73452, -0.01799, -0.00427, 0.00018829},
            {0.02804, 0.00772, 0.00083744, -0.00003387},
            {-0.00021988, -0.00005219, -7.44E-06, 2.77E-07},
            {1.08E-06, 2.47E-07, 4.87E-08, 3.79E-10}
        };

        // Placeholder for sumMoe (replace with your function)
        CppAD::AD<double> sumMOE = 0., MOE0 = 0., MOE1 = 0.;
        CppAD::AD<double> timeStepForT0 = 10 * (v - v_0) / a,
                          timeStepForT1 = 10 * (t_g - (v - v_0) / a);

        for (int ts = 0; ts < timeStepForT0; ts++){
            for (int m = 0; m <= 3; ++m) {
                for (int n = 0; n <= 3; ++n) {
                    MOE0 += M[m][n] * CppAD::pow((v_0 + a * ts)*3.6, m) * CppAD::pow(a*3.6, n);
                }
            }
        }
        MOE0 = 0.1 * CppAD::exp(MOE0);
        
        for (int i = 0; i <= 3; i++) {
            MOE1 += M[i][0] * CppAD::pow(v*3.6, i);
        }
        MOE1 = (t_g - (v - v_0) / a) * CppAD::exp(MOE1);

        sumMOE = MOE0 + MOE1;

        // Objective function
        fg[0] = lambda1 * sumMOE - lambda2 * v + lambda3 * CppAD::pow(D - d, 2);

        // Constraint 3: d < D
        fg[1] = D - d;

        // Constraint 4: (v - v_0) / a <= t_g
        fg[2] = v - v_0 - a * t_g;
    }
};

int main() {
    // Initialize variables and set bounds
    size_t nx = 2;  // Number of variables (a and v)
    size_t ng = 2;  // Number of constraints
    CppAD::vector<double> x0(nx), xl(nx), xu(nx);
    CppAD::vector<double> gl(ng), gu(ng);

    // Initial guess
    x0[0] = -0.08;  // Initial guess for a
    x0[1] = 4.0;  // Initial guess for v

    // Variable bounds
    xl[0] = -5.;  // Lower bound for a
    xu[0] = 3.;  // Upper bound for a
    xl[1] = 0.;  // Lower bound for v
    xu[1] = 20.0; // Upper bound for v

    // Constraint bounds (most of them are set to be non-negative)
    for(int i = 0; i < ng; ++i) {
        gl[i] = 0.0;
        gu[i] = 1.0e19;
    }

    // Create the FG_eval object
    FG_eval fg_eval;

    // IPOPT options
    std::string options;
    options += "Integer print_level  0\n";
    options += "String sb            yes\n";
    options += "Integer max_iter     10\n";
    options += "Numeric tol          1e-6\n";
    options += "String derivative_test   second-order\n";
    options += "Numeric point_perturbation_radius   0.\n";

    // Solve the problem
    CppAD::ipopt::solve_result<CppAD::vector<double>> solution;
    CppAD::ipopt::solve<CppAD::vector<double>, FG_eval>(options, x0, xl, xu, gl, gu, fg_eval, solution);

    // Output the solution
    std::cout << "Optimal a: " << solution.x[0] << std::endl;
    std::cout << "Optimal v: " << solution.x[1] << std::endl;


    std::cout << "d: " << (solution.x[1] * solution.x[1] - v_0 * v_0) / (2.0 * solution.x[0]) + solution.x[1] * (t_g - (solution.x[1] - v_0) / solution.x[0])<< std::endl;
    // std::cout << "t0: " << (solution.x[1] - v_0) / solution.x[0] << std::endl;

    // std::cout << "v_0: " << v_0 << std::endl << "t_g: " << t_g << std::endl;
    return 0;
}