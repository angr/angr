int arithmetic_f64(int t, double a, double b, double c, double d)
{
    double x = a * b;

    if (t < 10000) {
        x *= c;
        for (int i = 0; i < 100; i++) {
            x += d;
        }
    }

    if (t == 100) {
        x *= 3.14;
    }

    *(volatile double *)(0xdeadbeef) = x;

    return 0;
}

double add_f64(double a, double b)
{
    return a + b;
}

double max_f64(double a, double b)
{
    if (a > b)
        return a;
    return b;
}

double int_to_f64(int x)
{
    return (double)x;
}

int f64_to_int(double x)
{
    return (int)x;
}

double polynomial_f64(double x)
{
    return 3.0 * x * x + 2.0 * x + 1.0;
}

double sum_array_f64(double *arr, int n)
{
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

double mixed_args_f64(int a, double b, int c, double d)
{
    return a * b + c * d;
}

float add_f32(float a, float b)
{
    return a + b;
}

float max_f32(float a, float b)
{
    if (a > b)
        return a;
    return b;
}

float int_to_f32(int x)
{
    return (float)x;
}

int f32_to_int(float x)
{
    return (int)x;
}

double f32_to_f64(float x)
{
    return (double)x;
}

float f64_to_f32(double x)
{
    return (float)x;
}

float sum_array_f32(float *arr, int n)
{
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

double mixed_f32_f64(float a, double b, float c)
{
    return (double)a * b + (double)c;
}

__attribute__((noinline)) float square_f32(float x)
{
    return x * x;
}

float call_f32_func(float a, float b)
{
    return square_f32(a) + square_f32(b);
}

double deep_stack_f64(double a, double b, double c, double d, double e, double f)
{
    return a * b + c * d + e * f;
}

float cast_chain_f32(double x)
{
    float f = (float)x;
    double d = (double)f;
    float f2 = (float)d;
    return f2;
}

double negate_and_abs_f64(double x)
{
    double neg = -x;
    if (neg < 0.0)
        return -neg;
    return neg;
}

float bitcast_int_to_f32(unsigned int bits)
{
    float f;
    __builtin_memcpy(&f, &bits, sizeof(f));
    return f;
}

__attribute__((noinline)) double recursive_f64(double x, int n)
{
    if (n <= 0)
        return 1.0;
    return x * recursive_f64(x, n - 1);
}

double divide_f64(double a, double b)
{
    return a / b;
}

__attribute__((noinline)) double identity_f64(double x)
{
    return x;
}

double call_f64_func(double a, double b)
{
    return identity_f64(a) + identity_f64(b);
}

double chained_f64_calls(double x)
{
    return identity_f64(identity_f64(x));
}

double multi_return_f64(double a, double b, int sel)
{
    double result;
    if (sel == 0)
        result = a + b;
    else if (sel == 1)
        result = a - b;
    else
        result = a * b;
    return result;
}

int compare_lt_f64(double a, double b)
{
    return a < b;
}

int compare_eq_f64(double a, double b)
{
    return a == b;
}

double g_f64_value;

double read_global_f64(void)
{
    return g_f64_value;
}

void write_global_f64(double x)
{
    g_f64_value = x;
}

long double add_f80(long double a, long double b)
{
    return a + b;
}

long double mul_f80(long double a, long double b)
{
    return a * b;
}

long double max_f80(long double a, long double b)
{
    if (a > b)
        return a;
    return b;
}

long double f64_to_f80(double x)
{
    return (long double)x;
}

double f80_to_f64(long double x)
{
    return (double)x;
}

long double int_to_f80(int x)
{
    return (long double)x;
}

int f80_to_int(long double x)
{
    return (int)x;
}

double round_trip_f80(double x)
{
    long double tmp = (long double)x;
    tmp = tmp + 1.0L;
    return (double)tmp;
}

long double store_reload_f80(long double x)
{
    volatile long double tmp = x * 2.0L;
    return tmp + 1.0L;
}

double mixed_f64_f64_f80(double a, long double b)
{
    long double result = (long double)a + b;
    return (double)result;
}

long double polynomial_f80(long double x)
{
    return 3.0L * x * x + 2.0L * x + 1.0L;
}

long double mixed_f80_f64_f80(double a, long double b)
{
    return (long double)a + b;
}

long double sum_array_f80(long double *arr, int n)
{
    long double sum = 0.0L;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

struct point {
    double x;
    double y;
};

double struct_point_distance_sq(struct point *p)
{
    return p->x * p->x + p->y * p->y;
}

void struct_point_scale(struct point *p, double factor)
{
    p->x *= factor;
    p->y *= factor;
}

double struct_point_dot(struct point *a, struct point *b)
{
    return a->x * b->x + a->y * b->y;
}

struct particle {
    int id;
    float mass;
    double position;
    double velocity;
};

double struct_particle_energy(struct particle *p)
{
    return 0.5 * p->mass * p->velocity * p->velocity;
}

void struct_particle_step(struct particle *p, double dt)
{
    p->position += p->velocity * dt;
}

float divide_f32(float a, float b)
{
    return a / b;
}

float mul_f32(float a, float b)
{
    return a * b;
}

float negate_f32(float x)
{
    return -x;
}

float abs_f32(float x)
{
    return x < 0.0f ? -x : x;
}

float polynomial_f32(float x)
{
    return 3.0f * x * x + 2.0f * x + 1.0f;
}

int compare_eq_f32(float a, float b)
{
    return a == b;
}

int compare_lt_f32(float a, float b)
{
    return a < b;
}

float min_f32(float a, float b)
{
    return a < b ? a : b;
}

double const_f32_to_f64(void)
{
    return (double)3.14f;
}

float const_f64_to_f32(void)
{
    return (float)2.718;
}

double mul_f64(double a, double b)
{
    return a * b;
}

double negate_f64(double x)
{
    return -x;
}

double abs_f64(double x)
{
    return x < 0.0 ? -x : x;
}

double min_f64(double a, double b)
{
    return a < b ? a : b;
}

long double divide_f80(long double a, long double b)
{
    return a / b;
}

long double min_f80(long double a, long double b)
{
    return a < b ? a : b;
}

long double negate_f80(long double x)
{
    return -x;
}

long double abs_f80(long double x)
{
    return x < 0.0L ? -x : x;
}

int main(void) { return 0; }
