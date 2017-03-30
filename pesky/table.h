/*
BSD 3-Clause License

Copyright (c) 2017, John Ventura
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdint.h>

struct frequencytable {
    int channel;
    uint16_t frequency;
    int active;
};

const struct frequencytable freqtab[] = {
    {1, 2412},
    {2, 2417},
    {3, 2422},
    {4, 2427},
    {5, 2432},
    {6, 2437},
    {7, 2442},
    {8, 2447},
    {9, 2452},
    {10, 2457},
    {11, 2462},
    {12, 2467},
    {13, 2472},
    {14, 2484},
    {36, 5180},
    {40, 5200},
    {42, 5210},
    {44, 5220},
    {48, 5240},
    {50, 5250},
    {52, 5260},
    {56, 5280},
    {58, 5290},
    {60, 5300},
    {64, 5320},
    {149, 5745},
    {152, 5760},
    {153, 5765},
    {157, 5785},
    {160, 5800},
    {161, 5805},
    {165, 5825},
    {0, 0}
};
