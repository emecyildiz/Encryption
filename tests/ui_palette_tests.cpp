#include "ui_palette.h"
#include <algorithm>
#include <cmath>
#include <iostream>
double luminance(kasa::ui::Rgb c){
 auto linear=[](double v){return v<=0.04045?v/12.92:std::pow((v+0.055)/1.055,2.4);};
 return 0.2126*linear(c.r)+0.7152*linear(c.g)+0.0722*linear(c.b);
}
int main(){
 int failures=0,checks=0;
 auto check=[&](auto fg,auto bg){double a=luminance(fg),b=luminance(bg);double ratio=(std::max(a,b)+0.05)/(std::min(a,b)+0.05);++checks;if(ratio<4.5)++failures;std::cout<<"Contrast "<<ratio<<'\n';};
 using namespace kasa::ui;
 for(auto bg:{primary,primary_hover,primary_active})check(on_primary,bg);
 for(auto bg:{secondary,secondary_hover,secondary_active})check(on_secondary,bg);
 std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;
}
