
int gTemp = 0;

void comp(int a, int b)
{
    if(a == b)
    {
        gTemp |= 1;
    }
    if(a < b)
    {
        gTemp |= 1 << 1;
    }
    if(a <= b)
    {
        gTemp |= 1 << 2;
    }
    if(a > b)
    {
        gTemp |= 1 << 3;
    }
    if(a >= b)
    {
        gTemp |= 1 << 4;
    }
    if(a != b)
    {
        gTemp |= 1 << 5;
    }
    if(a == 0)
    {
        gTemp |= 1 << 6;
    }
    if(a > 0)
    {
        gTemp |= 1 << 7;
    }
    if(a >= 0)
    {
        gTemp |= 1 << 8;
    }
    if(a < 0)
    {
        gTemp |= 1 << 9;
    }
    if(a <= 0)
    {
        gTemp |= 1 << 10;
    }
    if(a != 0)
    {
        gTemp |= 1 << 11;
    }
}

int main()
{
    comp(0, 1);
    comp(-1, 10);
    return gTemp;
}
