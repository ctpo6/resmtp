#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

using namespace std;

void generator1(ofstream &of, int n)
{
  for (int i = 1, d = 1; i <= n; ++i, ++d) {
    of << d % 10;
    if (d % 70 == 0) {
      if (n - i >= 2) {
        of << "\n";
        ++i;
      }
    }
  }
}

void generator2(ofstream &of, int n)
{
  for (int i = 1, d = 1; i <= n; ++i, ++d) {
    of << d % 10;
    if (d % 70 == 0) {
      if (n - i >= 2) {
        of << "\r";
        ++i;
      }
    }
  }
}

void generator3(ofstream &of, int n)
{
  for (int i = 1, d = 1; i <= n; ++i, ++d) {
    of << d % 10;
    if (d % 70 == 0) {
      if (n - i >= 3) {
        of << "\r\n";
        i += 2;
      }
    }
  }
}


int main(int argc, char * argv[])
{
  if (argc < 3) {
    cout << "Usage: g <generator> <size>" << endl;
    return 1;
  }
  
  int n = atoi(argv[2]);
  if (n <= 0) {
    cout << "The <size> param must be a positive integer" << endl;
    return 1;
  }

  ofstream of("out.txt", ios_base::out | ios_base::binary);
  
  if (strcmp(argv[1], "1") == 0) {
    generator1(of, n);
  }
  else if (strcmp(argv[1], "2") == 0) {
    generator2(of, n);
  }
  else if (strcmp(argv[1], "3") == 0) {
    generator3(of, n);
  }
  else {
    return 1;
  }
  
  return 0;
}
