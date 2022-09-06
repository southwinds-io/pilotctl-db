/*
    Pilot Control Database - © 2018-Present - SouthWinds Tech Ltd - www.southwinds.io
    Licensed under the Apache License, Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0
    Contributors to this project, hereby assign copyright in this code to the project,
    to be licensed under the same terms as the rest of the code.
*/
DO
$$
    DECLARE
        rec RECORD;
        DROP_STATEMENT VARCHAR(200);
    BEGIN
        -- drops all functions that start with the FX_PATTERN prefix
        FOR rec IN
            SELECT routines.routine_name as fx_name
            FROM information_schema.routines
            WHERE routines.specific_schema='public'
            AND routines.routine_name SIMILAR TO 'pilotctl_*'
            ORDER BY routines.routine_name
        LOOP
            DROP_STATEMENT = 'DROP FUNCTION IF EXISTS ' || rec.fx_name || ' CASCADE;';
            EXECUTE DROP_STATEMENT;
        END LOOP;
    END;
$$