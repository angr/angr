import angr
from angr.utils.patch_analysis import PatchAnalysis


def main():
    patch = """
 }
 
 void rx_brake_routine( unsigned char buff[], struct Bumper *bumper ) {
-    int16_t speed_value;  // vulnerability here
+    uint16_t speed_value;  // vulnerability here
     uint8_t brake_switch;
     uint8_t prev_brake_state = bumper->brake_state;
     // Extract Speed and brake switch from frame
"""

    pa = PatchAnalysis()
    pa.analyze_patch(patch)


if __name__ == "__main__":
    main()
