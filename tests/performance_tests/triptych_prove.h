// Copyright (c) 2014-2021, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <stdlib.h>
#include "ringct/triptych.h"

using namespace rct;

template<size_t a_n, size_t a_m>
class test_triptych_prove
{
    public:
        static const size_t loop_count = 100;
        static const size_t n = a_n;
        static const size_t m = a_m;

        bool init()
        {
            const size_t N = pow(n,m); // anonymity set size

            M = keyV(N); // M[l] = Com(0,r)
            P = keyV(N); // P[l] = Com(a,s)
            l = 0;

            // Random keys
            key temp;
            for (size_t k = 0; k < N; k++)
            {
                skpkGen(temp,M[k]);
                skpkGen(temp,P[k]);
            }

            // Signing and commitment keys (assumes fixed signing index for this test)
            // TODO: random signing index
            skpkGen(r,M[l]); // M[l] = Com(0,r)

            a = skGen(); // P[l] = Com(a,s);
            s = skGen();
            addKeys2(P[l],s,a,H);

            s1 = skGen(); // C_offset = Com(a,s1)
            addKeys2(C_offset,s1,a,H);

            message = skGen();

            return true;
        }

        bool test()
        {
            // Build proof
            key temp;
            sc_sub(temp.bytes,s.bytes,s1.bytes);
            triptych_prove(M,P,C_offset,l,r,temp,n,m,message);

            return true;
        }

    private:
        keyV M;
        keyV P;
        size_t l;
        key r;
        key s;
        key s1;
        key a;
        key C_offset;
        key message;
        TriptychProof proof;
};
