package de.upb.ra.data.outpuModel;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * One SRM call site inside an application method.
 * If a method calls the same SRM at two places, there are two entries.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonPropertyOrder({"srmSignature", "lineNumber", "roles", "cwes", "weaknessCategory"})
public class InvokedSrmInfo {
    // Signature of the invoked SRM (or "@ResponseBody" for the annotation based sink)
    private String srmSignature;

    // Source line of the call site. It is -1 when the bytecode has no line number information.
    private int lineNumber;

    // All taint roles of the SRM from the SRM list (SOURCE, SINK, SANITIZER, PROPAGATOR)
    private List<String> roles;

    // All CWEs linked to the SRM from the SRM list
    private List<String> cwes;

    // Weakness category this call site was counted in
    private String weaknessCategory;
}
