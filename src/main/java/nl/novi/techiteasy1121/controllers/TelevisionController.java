package nl.novi.techiteasy1121.controllers;

import nl.novi.techiteasy1121.dtos.IdInputDto;
import nl.novi.techiteasy1121.dtos.TelevisionDto;
import nl.novi.techiteasy1121.dtos.TelevisionInputDto;
import nl.novi.techiteasy1121.dtos.WallBracketDto;
import nl.novi.techiteasy1121.services.TelevisionService;
import nl.novi.techiteasy1121.services.TelevisionWallBracketService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@RestController
public class TelevisionController {

    private final TelevisionService televisionService;

    private final TelevisionWallBracketService televisionWallBracketService;

    public TelevisionController(TelevisionService televisionService,
                                TelevisionWallBracketService televisionWallBracketService){
        this.televisionService = televisionService;
        this.televisionWallBracketService = televisionWallBracketService;
        float f = 1f;
        double d = 1d;
        long l = 1l;
    }

    @GetMapping("/televisions")
    public ResponseEntity<List<TelevisionDto>> getAllTelevisions(@RequestParam(value = "brand", required = false) Optional<String> brand) {

        List<TelevisionDto> dtos;

        if (brand.isEmpty()){

            dtos = televisionService.getAllTelevisions();

        } else {

            dtos = televisionService.getAllTelevisionsByBrand(brand.get());

        }

        return ResponseEntity.ok().body(dtos);

    }

    @GetMapping("/televisions/{id}")
    public ResponseEntity<TelevisionDto> getTelevision(@PathVariable("id")Long id) {

        TelevisionDto television = televisionService.getTelevisionById(id);

            return ResponseEntity.ok().body(television);

    }

    @PostMapping("/televisions")
    public ResponseEntity<Object> addTelevision(@Valid @RequestBody TelevisionInputDto televisionInputDto) {

        TelevisionDto dto = televisionService.addTelevision(televisionInputDto);

        return ResponseEntity.created(null).body(dto);

    }

    @DeleteMapping("/televisions/{id}")
    public ResponseEntity<Object> deleteTelevision(@PathVariable Long id) {

        televisionService.deleteTelevision(id);

        return ResponseEntity.noContent().build();

    }

    @PutMapping("/televisions/{id}")
    public ResponseEntity<Object> updateTelevision(@PathVariable Long id, @Valid @RequestBody TelevisionInputDto newTelevision) {

        TelevisionDto dto = televisionService.updateTelevision(id, newTelevision);

        return ResponseEntity.ok().body(dto);
    }

    // Onderstaande 2 methodes zijn endpoints om andere entiteiten toe te voegen aan de Television.
    // Dit is ????n manier om dit te doen, met ????n PathVariable en ????n RequestBody.
    @PutMapping("/televisions/{id}/remotecontroller")
    public void assignRemoteControllerToTelevision(@PathVariable("id") Long id,@Valid @RequestBody IdInputDto input) {
        televisionService.assignRemoteControllerToTelevision(id, input.id);
    }

    //Dit is een andere manier om het te doen, met twee Pathvariables, maar het kan uiteraard ook anders.
    @PutMapping("/televisions/{id}/{ciModuleId}")
    public void assignCIModuleToTelevision(@PathVariable("id") Long id, @PathVariable("ciModuleId") Long ciModuleId) {
        televisionService.assignCIModuleToTelevision(id, ciModuleId);
    }

    // Deze methode is om alle wallbrackets op te halen die aan een bepaalde television gekoppeld zijn.
    // Deze methode maakt gebruik van de televisionWallBracketService.
    @GetMapping("/televisions/wallBrackets/{televisionId}")
    public Collection<WallBracketDto> getWallBracketsByTelevisionId(@PathVariable("televisionId") Long televisionId){
        return televisionWallBracketService.getWallBracketsByTelevisionId(televisionId);
    }
}
