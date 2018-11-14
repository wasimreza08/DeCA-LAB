package analysis.exercise1;

import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;
import soot.Body;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.StringConstant;

import java.util.List;

public class MisuseAnalysis extends AbstractAnalysis {
    public MisuseAnalysis(Body body, VulnerabilityReporter reporter) {
        super(body, reporter);
    }

    @Override
    protected void flowThrough(Unit unit) {
        // TODO: Implement your analysis here.
        List<ValueBox> value = unit.getUseBoxes();
        int i = 0;
        while (true) {
            if (value.size() == i) {
                break;
            }

            if (value.get(i).getValue().toString().equals("staticinvoke <javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>(\"AES\")")) {
                //   System.out.println("got the bug \n");
                reporter.reportVulnerability(method.getSignature(), unit);
            }
            i++;
        }
    }
}
