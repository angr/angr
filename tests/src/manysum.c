int sum(int a, int b) {
    return a + b;
}

int sumlots(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k) {
    return sum(sum(sum(sum(a, b), sum(c, d)), sum(sum(e, f), sum(g, h))), sum(sum(i, j), k));
}

int main(int argc, char** argv) {
    return sumlots(1,2,3,4,5,6,7,8,9,10,11) != 66;
}
